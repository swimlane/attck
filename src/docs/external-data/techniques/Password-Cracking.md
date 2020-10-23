
# Password Cracking

## Description

### MITRE Description

> Adversaries may use password cracking to attempt to recover usable credentials, such as plaintext passwords, when credential material such as password hashes are obtained. [OS Credential Dumping](https://attack.mitre.org/techniques/T1003) is used to obtain password hashes, this may only get an adversary so far when [Pass the Hash](https://attack.mitre.org/techniques/T1550/002) is not an option. Techniques to systematically guess the passwords used to compute hashes are available, or the adversary may use a pre-computed rainbow table to crack hashes. Cracking hashes is usually done on adversary-controlled systems outside of the target network.(Citation: Wikipedia Password cracking) The resulting plaintext password resulting from a successfully cracked hash may be used to log into systems, resources, and services in which the account has access.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows', 'Office 365', 'Azure AD']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1110/002

## Potential Commands

```
cd #{hashcat_exe}\..
#{hashcat_exe} -a 0 -m 1000 -r .\rules\Incisive-leetspeak.rule #{input_file_sam} PathToAtomicsFolder\T1110.002\src\password.lst
cd %temp%\hashcat6\hashcat-6.1.1\hashcat.exe\..
%temp%\hashcat6\hashcat-6.1.1\hashcat.exe -a 0 -m 1000 -r .\rules\Incisive-leetspeak.rule #{input_file_sam} #{input_file_passwords}
cd #{hashcat_exe}\..
#{hashcat_exe} -a 0 -m 1000 -r .\rules\Incisive-leetspeak.rule PathToAtomicsFolder\T1110.002\src\sam.txt #{input_file_passwords}
```

## Commands Dataset

```
[{'command': 'cd %temp%\\hashcat6\\hashcat-6.1.1\\hashcat.exe\\..\n'
             '%temp%\\hashcat6\\hashcat-6.1.1\\hashcat.exe -a 0 -m 1000 -r '
             '.\\rules\\Incisive-leetspeak.rule #{input_file_sam} '
             '#{input_file_passwords}',
  'name': None,
  'source': 'atomics/T1110.002/T1110.002.yaml'},
 {'command': 'cd #{hashcat_exe}\\..\n'
             '#{hashcat_exe} -a 0 -m 1000 -r .\\rules\\Incisive-leetspeak.rule '
             'PathToAtomicsFolder\\T1110.002\\src\\sam.txt '
             '#{input_file_passwords}',
  'name': None,
  'source': 'atomics/T1110.002/T1110.002.yaml'},
 {'command': 'cd #{hashcat_exe}\\..\n'
             '#{hashcat_exe} -a 0 -m 1000 -r .\\rules\\Incisive-leetspeak.rule '
             '#{input_file_sam} '
             'PathToAtomicsFolder\\T1110.002\\src\\password.lst',
  'name': None,
  'source': 'atomics/T1110.002/T1110.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Brute Force: Password Cracking': {'atomic_tests': [{'auto_generated_guid': '6d27df5d-69d4-4c91-bc33-5983ffe91692',
                                                                              'dependencies': [{'description': 'Hashcat '
                                                                                                               'must '
                                                                                                               'exist '
                                                                                                               'on '
                                                                                                               'disk '
                                                                                                               'at '
                                                                                                               'specified '
                                                                                                               'location '
                                                                                                               '(#{hashcat_exe})',
                                                                                                'get_prereq_command': 'Invoke-WebRequest '
                                                                                                                      '"https://www.7-zip.org/a/7z1900.exe" '
                                                                                                                      '-OutFile '
                                                                                                                      '"$env:TEMP\\7z1900.exe"\n'
                                                                                                                      'Start-Process '
                                                                                                                      '-FilePath '
                                                                                                                      '"$env:Temp\\7z1900.exe" '
                                                                                                                      '-ArgumentList '
                                                                                                                      '"/S '
                                                                                                                      '/D=$env:temp\\7zi" '
                                                                                                                      '-NoNewWindow\n'
                                                                                                                      'Invoke-WebRequest '
                                                                                                                      '"https://hashcat.net/files/hashcat-6.1.1.7z" '
                                                                                                                      '-OutFile '
                                                                                                                      '"$env:TEMP\\hashcat6.7z"\n'
                                                                                                                      'Start-Process '
                                                                                                                      'cmd.exe '
                                                                                                                      '-Args  '
                                                                                                                      '"/c '
                                                                                                                      '%temp%\\7z\\7z.exe '
                                                                                                                      'x '
                                                                                                                      '%temp%\\hashcat6.7z '
                                                                                                                      '-aoa '
                                                                                                                      '-o%temp%\\hashcat-unzip" '
                                                                                                                      '-Wait\n'
                                                                                                                      'New-Item '
                                                                                                                      '-ItemType '
                                                                                                                      'Directory '
                                                                                                                      '(Split-Path '
                                                                                                                      '$(cmd '
                                                                                                                      '/c '
                                                                                                                      'echo '
                                                                                                                      '#{hashcat_exe})) '
                                                                                                                      '-Force '
                                                                                                                      '| '
                                                                                                                      'Out-Null\n'
                                                                                                                      'Move-Item '
                                                                                                                      '$env:Temp\\hashcat-unzip\\hashcat-6.1.1\\* '
                                                                                                                      '$(cmd '
                                                                                                                      '/c '
                                                                                                                      'echo '
                                                                                                                      '#{hashcat_exe}\\..) '
                                                                                                                      '-Force '
                                                                                                                      '-ErrorAction '
                                                                                                                      'Ignore',
                                                                                                'prereq_command': 'if '
                                                                                                                  '(Test-Path  '
                                                                                                                  '$(cmd '
                                                                                                                  '/c '
                                                                                                                  'echo '
                                                                                                                  '#{hashcat_exe})) '
                                                                                                                  '{exit '
                                                                                                                  '0} '
                                                                                                                  'else '
                                                                                                                  '{exit '
                                                                                                                  '1}'}],
                                                                              'dependency_executor_name': 'powershell',
                                                                              'description': 'Execute '
                                                                                             'Hashcat.exe '
                                                                                             'with '
                                                                                             'provided '
                                                                                             'SAM '
                                                                                             'file '
                                                                                             'from '
                                                                                             'registry '
                                                                                             'of '
                                                                                             'Windows '
                                                                                             'and '
                                                                                             'Password '
                                                                                             'list '
                                                                                             'to '
                                                                                             'crack '
                                                                                             'against',
                                                                              'executor': {'cleanup_command': 'del '
                                                                                                              '%temp%\\hashcat6.7z '
                                                                                                              '>nul '
                                                                                                              '2>&1\n'
                                                                                                              'del '
                                                                                                              '%temp%\\7z1900.exe '
                                                                                                              '>nul '
                                                                                                              '2>&1\n'
                                                                                                              'del '
                                                                                                              '%temp%\\7z '
                                                                                                              '/Q '
                                                                                                              '/S '
                                                                                                              '>nul '
                                                                                                              '2>&1\n'
                                                                                                              'del '
                                                                                                              '%temp%\\hashcat-unzip '
                                                                                                              '/Q '
                                                                                                              '/S '
                                                                                                              '>nul '
                                                                                                              '2>&1',
                                                                                           'command': 'cd '
                                                                                                      '#{hashcat_exe}\\..\n'
                                                                                                      '#{hashcat_exe} '
                                                                                                      '-a '
                                                                                                      '0 '
                                                                                                      '-m '
                                                                                                      '1000 '
                                                                                                      '-r '
                                                                                                      '.\\rules\\Incisive-leetspeak.rule '
                                                                                                      '#{input_file_sam} '
                                                                                                      '#{input_file_passwords}',
                                                                                           'elevation_required': True,
                                                                                           'name': 'command_prompt'},
                                                                              'input_arguments': {'hashcat_exe': {'default': '%temp%\\hashcat6\\hashcat-6.1.1\\hashcat.exe',
                                                                                                                  'description': 'Path '
                                                                                                                                 'to '
                                                                                                                                 'Hashcat '
                                                                                                                                 'executable',
                                                                                                                  'type': 'String'},
                                                                                                  'input_file_passwords': {'default': 'PathToAtomicsFolder\\T1110.002\\src\\password.lst',
                                                                                                                           'description': 'Path '
                                                                                                                                          'to '
                                                                                                                                          'password '
                                                                                                                                          'list',
                                                                                                                           'type': 'string'},
                                                                                                  'input_file_sam': {'default': 'PathToAtomicsFolder\\T1110.002\\src\\sam.txt',
                                                                                                                     'description': 'Path '
                                                                                                                                    'to '
                                                                                                                                    'SAM '
                                                                                                                                    'file',
                                                                                                                     'type': 'string'}},
                                                                              'name': 'Password '
                                                                                      'Cracking '
                                                                                      'with '
                                                                                      'Hashcat',
                                                                              'supported_platforms': ['windows']}],
                                                            'attack_technique': 'T1110.002',
                                                            'display_name': 'Brute '
                                                                            'Force: '
                                                                            'Password '
                                                                            'Cracking'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [Multi-factor Authentication](../mitigations/Multi-factor-Authentication.md)

* [Password Policies](../mitigations/Password-Policies.md)
    

# Actors


* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)

* [APT3](../actors/APT3.md)
    
* [APT41](../actors/APT41.md)
    
