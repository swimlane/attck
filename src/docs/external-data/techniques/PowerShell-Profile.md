
# PowerShell Profile

## Description

### MITRE Description

> Adversaries may gain persistence and elevate privileges in certain situations by abusing [PowerShell](https://attack.mitre.org/techniques/T1086) profiles. A PowerShell profile  (<code>profile.ps1</code>) is a script that runs when PowerShell starts and can be used as a logon script to customize user environments. PowerShell supports several profiles depending on the user or host program. For example, there can be different profiles for PowerShell host programs such as the PowerShell console, PowerShell ISE or Visual Studio Code. An administrator can also configure a profile that applies to all users and host programs on the local computer. (Citation: Microsoft About Profiles) 

Adversaries may modify these profiles to include arbitrary commands, functions, modules, and/or PowerShell drives to gain persistence. Every time a user opens a PowerShell session the modified script will be executed unless the <code>-NoProfile</code> flag is used when it is launched. (Citation: ESET Turla PowerShell May 2019) 

An adversary may also be able to escalate privileges if a script in a PowerShell profile is loaded and executed by an account with higher privileges, such as a domain administrator. (Citation: Wits End and Shady PowerShell Profiles)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1504

## Potential Commands

```
Add-Content #{ps_profile} -Value ""
Add-Content #{ps_profile} -Value "Start-Process calc.exe"
powershell -Command exit

Add-Content $profile -Value ""
Add-Content $profile -Value "Start-Process #{exe_path}"
powershell -Command exit

```

## Commands Dataset

```
[{'command': 'Add-Content #{ps_profile} -Value ""\n'
             'Add-Content #{ps_profile} -Value "Start-Process calc.exe"\n'
             'powershell -Command exit\n',
  'name': None,
  'source': 'atomics/T1504/T1504.yaml'},
 {'command': 'Add-Content $profile -Value ""\n'
             'Add-Content $profile -Value "Start-Process #{exe_path}"\n'
             'powershell -Command exit\n',
  'name': None,
  'source': 'atomics/T1504/T1504.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - PowerShell Profile': {'atomic_tests': [{'auto_generated_guid': '090e5aa5-32b6-473b-a49b-21e843a56896',
                                                                  'dependencies': [{'description': 'Ensure '
                                                                                                   'a '
                                                                                                   'powershell '
                                                                                                   'profile '
                                                                                                   'exists '
                                                                                                   'for '
                                                                                                   'the '
                                                                                                   'current '
                                                                                                   'user\n',
                                                                                    'get_prereq_command': 'New-Item '
                                                                                                          '-Path '
                                                                                                          '#{ps_profile} '
                                                                                                          '-Type '
                                                                                                          'File '
                                                                                                          '-Force\n',
                                                                                    'prereq_command': 'if '
                                                                                                      '(Test-Path '
                                                                                                      '#{ps_profile}) '
                                                                                                      '{exit '
                                                                                                      '0} '
                                                                                                      'else '
                                                                                                      '{exit '
                                                                                                      '1}\n'}],
                                                                  'dependency_executor_name': 'powershell',
                                                                  'description': 'Appends '
                                                                                 'a '
                                                                                 'start '
                                                                                 'process '
                                                                                 'cmdlet '
                                                                                 'to '
                                                                                 'the '
                                                                                 'current '
                                                                                 "user's "
                                                                                 'powershell '
                                                                                 'profile '
                                                                                 'pofile '
                                                                                 'that '
                                                                                 'points '
                                                                                 'to '
                                                                                 'a '
                                                                                 'malicious '
                                                                                 'executable. '
                                                                                 'Upon '
                                                                                 'execution, '
                                                                                 'calc.exe '
                                                                                 'will '
                                                                                 'be '
                                                                                 'launched.\n',
                                                                  'executor': {'cleanup_command': '$oldprofile '
                                                                                                  '= '
                                                                                                  'cat '
                                                                                                  '$profile '
                                                                                                  '| '
                                                                                                  'Select-Object '
                                                                                                  '-skiplast '
                                                                                                  '1\n'
                                                                                                  'Set-Content '
                                                                                                  '$profile '
                                                                                                  '-Value '
                                                                                                  '$oldprofile\n',
                                                                               'command': 'Add-Content '
                                                                                          '#{ps_profile} '
                                                                                          '-Value '
                                                                                          '""\n'
                                                                                          'Add-Content '
                                                                                          '#{ps_profile} '
                                                                                          '-Value '
                                                                                          '"Start-Process '
                                                                                          '#{exe_path}"\n'
                                                                                          'powershell '
                                                                                          '-Command '
                                                                                          'exit\n',
                                                                               'elevation_required': False,
                                                                               'name': 'powershell'},
                                                                  'input_arguments': {'exe_path': {'default': 'calc.exe',
                                                                                                   'description': 'Path '
                                                                                                                  'the '
                                                                                                                  'malicious '
                                                                                                                  'executable',
                                                                                                   'type': 'Path'},
                                                                                      'ps_profile': {'default': '$profile',
                                                                                                     'description': 'Powershell '
                                                                                                                    'profile '
                                                                                                                    'to '
                                                                                                                    'use',
                                                                                                     'type': 'String'}},
                                                                  'name': 'Append '
                                                                          'malicious '
                                                                          'start-process '
                                                                          'cmdlet',
                                                                  'supported_platforms': ['windows']}],
                                                'attack_technique': 'T1504',
                                                'display_name': 'PowerShell '
                                                                'Profile'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors


* [Turla](../actors/Turla.md)

