
# Logon Script (Windows)

## Description

### MITRE Description

> Adversaries may use Windows logon scripts automatically executed at logon initialization to establish persistence. Windows allows logon scripts to be run whenever a specific user or group of users log into a system.(Citation: TechNet Logon Scripts) This is done via adding a path to a script to the <code>HKCU\Environment\UserInitMprLogonScript</code> Registry key.(Citation: Hexacorn Logon Scripts)

Adversaries may use these scripts to maintain persistence on a single system. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary. 

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1037/001

## Potential Commands

```
echo "echo Art "Logon Script" atomic test was successful. >> %USERPROFILE%\desktop\T1037.001-log.txt" > #{script_path}
REG.exe ADD HKCU\Environment /v UserInitMprLogonScript /t REG_SZ /d "#{script_path}" /f
echo "#{script_command}" > %temp%\art.bat
REG.exe ADD HKCU\Environment /v UserInitMprLogonScript /t REG_SZ /d "%temp%\art.bat" /f
```

## Commands Dataset

```
[{'command': 'echo "#{script_command}" > %temp%\\art.bat\n'
             'REG.exe ADD HKCU\\Environment /v UserInitMprLogonScript /t '
             'REG_SZ /d "%temp%\\art.bat" /f\n',
  'name': None,
  'source': 'atomics/T1037.001/T1037.001.yaml'},
 {'command': 'echo "echo Art "Logon Script" atomic test was successful. >> '
             '%USERPROFILE%\\desktop\\T1037.001-log.txt" > #{script_path}\n'
             'REG.exe ADD HKCU\\Environment /v UserInitMprLogonScript /t '
             'REG_SZ /d "#{script_path}" /f\n',
  'name': None,
  'source': 'atomics/T1037.001/T1037.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Boot or Logon Initialization Scripts: Logon Script (Windows)': {'atomic_tests': [{'auto_generated_guid': 'd6042746-07d4-4c92-9ad8-e644c114a231',
                                                                                                            'description': 'Adds '
                                                                                                                           'a '
                                                                                                                           'registry '
                                                                                                                           'value '
                                                                                                                           'to '
                                                                                                                           'run '
                                                                                                                           'batch '
                                                                                                                           'script '
                                                                                                                           'created '
                                                                                                                           'in '
                                                                                                                           'the '
                                                                                                                           '%temp% '
                                                                                                                           'directory. '
                                                                                                                           'Upon '
                                                                                                                           'execution, '
                                                                                                                           'there '
                                                                                                                           'will '
                                                                                                                           'be '
                                                                                                                           'a '
                                                                                                                           'new '
                                                                                                                           'environment '
                                                                                                                           'variable '
                                                                                                                           'in '
                                                                                                                           'the '
                                                                                                                           'HKCU\\Environment '
                                                                                                                           'key\n'
                                                                                                                           'that '
                                                                                                                           'can '
                                                                                                                           'be '
                                                                                                                           'viewed '
                                                                                                                           'in '
                                                                                                                           'the '
                                                                                                                           'Registry '
                                                                                                                           'Editor.\n',
                                                                                                            'executor': {'cleanup_command': 'REG.exe '
                                                                                                                                            'DELETE '
                                                                                                                                            'HKCU\\Environment '
                                                                                                                                            '/v '
                                                                                                                                            'UserInitMprLogonScript '
                                                                                                                                            '/f '
                                                                                                                                            '>nul '
                                                                                                                                            '2>&1\n'
                                                                                                                                            'del '
                                                                                                                                            '#{script_path} '
                                                                                                                                            '>nul '
                                                                                                                                            '2>&1\n'
                                                                                                                                            'del '
                                                                                                                                            '"%USERPROFILE%\\desktop\\T1037.001-log.txt" '
                                                                                                                                            '>nul '
                                                                                                                                            '2>&1\n',
                                                                                                                         'command': 'echo '
                                                                                                                                    '"#{script_command}" '
                                                                                                                                    '> '
                                                                                                                                    '#{script_path}\n'
                                                                                                                                    'REG.exe '
                                                                                                                                    'ADD '
                                                                                                                                    'HKCU\\Environment '
                                                                                                                                    '/v '
                                                                                                                                    'UserInitMprLogonScript '
                                                                                                                                    '/t '
                                                                                                                                    'REG_SZ '
                                                                                                                                    '/d '
                                                                                                                                    '"#{script_path}" '
                                                                                                                                    '/f\n',
                                                                                                                         'name': 'command_prompt'},
                                                                                                            'input_arguments': {'script_command': {'default': 'echo '
                                                                                                                                                              'Art '
                                                                                                                                                              '"Logon '
                                                                                                                                                              'Script" '
                                                                                                                                                              'atomic '
                                                                                                                                                              'test '
                                                                                                                                                              'was '
                                                                                                                                                              'successful. '
                                                                                                                                                              '>> '
                                                                                                                                                              '%USERPROFILE%\\desktop\\T1037.001-log.txt',
                                                                                                                                                   'description': 'Command '
                                                                                                                                                                  'To '
                                                                                                                                                                  'Execute',
                                                                                                                                                   'type': 'String'},
                                                                                                                                'script_path': {'default': '%temp%\\art.bat',
                                                                                                                                                'description': 'Path '
                                                                                                                                                               'to '
                                                                                                                                                               '.bat '
                                                                                                                                                               'file',
                                                                                                                                                'type': 'String'}},
                                                                                                            'name': 'Logon '
                                                                                                                    'Scripts',
                                                                                                            'supported_platforms': ['windows']}],
                                                                                          'attack_technique': 'T1037.001',
                                                                                          'display_name': 'Boot '
                                                                                                          'or '
                                                                                                          'Logon '
                                                                                                          'Initialization '
                                                                                                          'Scripts: '
                                                                                                          'Logon '
                                                                                                          'Script '
                                                                                                          '(Windows)'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Restrict Registry Permissions](../mitigations/Restrict-Registry-Permissions.md)


# Actors


* [APT28](../actors/APT28.md)

* [Cobalt Group](../actors/Cobalt-Group.md)
    
