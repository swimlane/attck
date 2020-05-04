
# Credentials in Registry

## Description

### MITRE Description

> The Windows Registry stores configuration information that can be used by the system or other programs. Adversaries may query the Registry looking for credentials and passwords that have been stored for use by other programs or services. Sometimes these credentials are used for automatic logons.

Example commands to find Registry keys related to password information: (Citation: Pentestlab Stored Credentials)

* Local Machine Hive: <code>reg query HKLM /f password /t REG_SZ /s</code>
* Current User Hive: <code>reg query HKCU /f password /t REG_SZ /s</code>

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User', 'Administrator']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1214

## Potential Commands

```
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

reg query HKCU\Software\SimonTatham\PuTTY\Sessions /t REG_SZ /s

{'windows': {'psh': {'command': 'reg query HKCU /f password /t REG_SZ /s\n'}}}
```

## Commands Dataset

```
[{'command': 'reg query HKLM /f password /t REG_SZ /s\n'
             'reg query HKCU /f password /t REG_SZ /s\n',
  'name': None,
  'source': 'atomics/T1214/T1214.yaml'},
 {'command': 'reg query HKCU\\Software\\SimonTatham\\PuTTY\\Sessions /t REG_SZ '
             '/s\n',
  'name': None,
  'source': 'atomics/T1214/T1214.yaml'},
 {'command': {'windows': {'psh': {'command': 'reg query HKCU /f password /t '
                                             'REG_SZ /s\n'}}},
  'name': 'Search for possible credentials stored in Registry',
  'source': 'data/abilities/credential-access/3aad5312-d48b-4206-9de4-39866c12e60f.yml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Credentials In Registry',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_command_line contains "reg '
           'query HKLM \\\\/f password \\\\/t REG_SZ \\\\/s"or '
           'process_command_line contains "reg query HKCU \\\\/f password '
           '\\\\/t REG_SZ \\\\/s"or process_command_line contains '
           '"Get-UnattendedInstallFile"or process_command_line contains '
           '"Get-Webconfig"or process_command_line contains '
           '"Get-ApplicationHost"or process_command_line contains '
           '"Get-SiteListPassword"or process_command_line contains '
           '"Get-CachedGPPPassword"or process_command_line contains '
           '"Get-RegistryAutoLogon")'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: credentials to enumerate the registry\n'
           'description: win7 test\n'
           'references: http://www.rinige.com/index.php/archives/770/\n'
           'tags: T1214\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: sysmon\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 1 # Process Creation\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Image: 'C: \\ * \\ reg.exe'\n"
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0OriginalFileName: reg.exe\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0CommandLine: \'reg query "HKLM \\ '
           'SOFTWARE \\ Microsoft \\ Windows NT \\ Currentversion \\ '
           'Winlogon"\'\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0ParentCommandLine: "C: \\ * \\ '
           'cmd.exe"\n'
           '\xa0\xa0\xa0\xa0condition: selection\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Credentials in Registry': {'atomic_tests': [{'description': 'Queries '
                                                                                      'to '
                                                                                      'enumerate '
                                                                                      'for '
                                                                                      'credentials '
                                                                                      'in '
                                                                                      'the '
                                                                                      'Registry. '
                                                                                      'Upon '
                                                                                      'execution, '
                                                                                      'any '
                                                                                      'registry '
                                                                                      'key '
                                                                                      'containing '
                                                                                      'the '
                                                                                      'word '
                                                                                      '"password" '
                                                                                      'will '
                                                                                      'be '
                                                                                      'displayed.\n',
                                                                       'executor': {'command': 'reg '
                                                                                               'query '
                                                                                               'HKLM '
                                                                                               '/f '
                                                                                               'password '
                                                                                               '/t '
                                                                                               'REG_SZ '
                                                                                               '/s\n'
                                                                                               'reg '
                                                                                               'query '
                                                                                               'HKCU '
                                                                                               '/f '
                                                                                               'password '
                                                                                               '/t '
                                                                                               'REG_SZ '
                                                                                               '/s\n',
                                                                                    'elevation_required': False,
                                                                                    'name': 'command_prompt'},
                                                                       'name': 'Enumeration '
                                                                               'for '
                                                                               'Credentials '
                                                                               'in '
                                                                               'Registry',
                                                                       'supported_platforms': ['windows']},
                                                                      {'description': 'Queries '
                                                                                      'to '
                                                                                      'enumerate '
                                                                                      'for '
                                                                                      'PuTTY '
                                                                                      'credentials '
                                                                                      'in '
                                                                                      'the '
                                                                                      'Registry. '
                                                                                      'PuTTY '
                                                                                      'must '
                                                                                      'be '
                                                                                      'installed '
                                                                                      'for '
                                                                                      'this '
                                                                                      'test '
                                                                                      'to '
                                                                                      'work. '
                                                                                      'If '
                                                                                      'any '
                                                                                      'registry\n'
                                                                                      'entries '
                                                                                      'are '
                                                                                      'found, '
                                                                                      'they '
                                                                                      'will '
                                                                                      'be '
                                                                                      'displayed.\n',
                                                                       'executor': {'command': 'reg '
                                                                                               'query '
                                                                                               'HKCU\\Software\\SimonTatham\\PuTTY\\Sessions '
                                                                                               '/t '
                                                                                               'REG_SZ '
                                                                                               '/s\n',
                                                                                    'elevation_required': False,
                                                                                    'name': 'command_prompt'},
                                                                       'name': 'Enumeration '
                                                                               'for '
                                                                               'PuTTY '
                                                                               'Credentials '
                                                                               'in '
                                                                               'Registry',
                                                                       'supported_platforms': ['windows']}],
                                                     'attack_technique': 'T1214',
                                                     'display_name': 'Credentials '
                                                                     'in '
                                                                     'Registry'}},
 {'Mitre Stockpile - Search for possible credentials stored in Registry': {'description': 'Search '
                                                                                          'for '
                                                                                          'possible '
                                                                                          'credentials '
                                                                                          'stored '
                                                                                          'in '
                                                                                          'Registry',
                                                                           'id': '3aad5312-d48b-4206-9de4-39866c12e60f',
                                                                           'name': 'Credentials '
                                                                                   'in '
                                                                                   'Registry',
                                                                           'platforms': {'windows': {'psh': {'command': 'reg '
                                                                                                                        'query '
                                                                                                                        'HKCU '
                                                                                                                        '/f '
                                                                                                                        'password '
                                                                                                                        '/t '
                                                                                                                        'REG_SZ '
                                                                                                                        '/s\n'}}},
                                                                           'tactic': 'credential-access',
                                                                           'technique': {'attack_id': 'T1214',
                                                                                         'name': 'Credentials '
                                                                                                 'in '
                                                                                                 'Registry'}}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations

None

# Actors


* [Soft Cell](../actors/Soft-Cell.md)

