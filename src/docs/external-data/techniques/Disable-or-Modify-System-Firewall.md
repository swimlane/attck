
# Disable or Modify System Firewall

## Description

### MITRE Description

> Adversaries may disable or modify system firewalls in order to bypass controls limiting network usage. Changes could be disabling the entire mechanism as well as adding, deleting, or modifying particular rules. This can be done numerous ways depending on the operating system, including via command-line, editing Windows Registry keys, and Windows Control Panel.

Modifying or disabling a system firewall may enable adversary C2 communications, lateral movement, and/or data exfiltration that would otherwise not be allowed. 

## Aliases

```

```

## Additional Attributes

* Bypass: ['Firewall']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1562/004

## Potential Commands

```
netsh advfirewall firewall add rule name="atomic testing" action=allow dir=in protocol=TCP localport=450
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
netsh advfirewall firewall set rule group="file and printer sharing" new enable=Yes
netsh advfirewall firewall add rule name="Atomic Test" dir=in action=allow program="C:\Users\$env:UserName\AtomicTest.exe" enable=yes
if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "6" ];
then
  service iptables stop
  chkconfig off iptables
  service ip6tables stop
  chkconfig off ip6tables
else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "7" ];
  systemctl stop firewalld
  systemctl disable firewalld
fi
netsh advfirewall set currentprofile state off
```

## Commands Dataset

```
[{'command': "if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -eq "
             '"6" ];\n'
             'then\n'
             '  service iptables stop\n'
             '  chkconfig off iptables\n'
             '  service ip6tables stop\n'
             '  chkconfig off ip6tables\n'
             "else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) "
             '-eq "7" ];\n'
             '  systemctl stop firewalld\n'
             '  systemctl disable firewalld\n'
             'fi\n',
  'name': None,
  'source': 'atomics/T1562.004/T1562.004.yaml'},
 {'command': 'netsh advfirewall set currentprofile state off\n',
  'name': None,
  'source': 'atomics/T1562.004/T1562.004.yaml'},
 {'command': 'netsh advfirewall firewall set rule group="remote desktop" new '
             'enable=Yes\n'
             'netsh advfirewall firewall set rule group="file and printer '
             'sharing" new enable=Yes\n',
  'name': None,
  'source': 'atomics/T1562.004/T1562.004.yaml'},
 {'command': 'netsh advfirewall firewall add rule name="atomic testing" '
             'action=allow dir=in protocol=TCP localport=450 \n',
  'name': None,
  'source': 'atomics/T1562.004/T1562.004.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1562.004/T1562.004.yaml'},
 {'command': 'netsh advfirewall firewall add rule name="Atomic Test" dir=in '
             'action=allow program="C:\\Users\\$env:UserName\\AtomicTest.exe" '
             'enable=yes',
  'name': None,
  'source': 'atomics/T1562.004/T1562.004.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Impair Defenses: Disable or Modify System Firewall': {'atomic_tests': [{'auto_generated_guid': '80f5e701-f7a4-4d06-b140-26c8efd1b6b4',
                                                                                                  'description': 'Disables '
                                                                                                                 'the '
                                                                                                                 'iptables '
                                                                                                                 'firewall\n',
                                                                                                  'executor': {'command': 'if '
                                                                                                                          '[ '
                                                                                                                          '$(rpm '
                                                                                                                          '-q '
                                                                                                                          '--queryformat '
                                                                                                                          "'%{VERSION}' "
                                                                                                                          'centos-release) '
                                                                                                                          '-eq '
                                                                                                                          '"6" '
                                                                                                                          '];\n'
                                                                                                                          'then\n'
                                                                                                                          '  '
                                                                                                                          'service '
                                                                                                                          'iptables '
                                                                                                                          'stop\n'
                                                                                                                          '  '
                                                                                                                          'chkconfig '
                                                                                                                          'off '
                                                                                                                          'iptables\n'
                                                                                                                          '  '
                                                                                                                          'service '
                                                                                                                          'ip6tables '
                                                                                                                          'stop\n'
                                                                                                                          '  '
                                                                                                                          'chkconfig '
                                                                                                                          'off '
                                                                                                                          'ip6tables\n'
                                                                                                                          'else '
                                                                                                                          'if '
                                                                                                                          '[ '
                                                                                                                          '$(rpm '
                                                                                                                          '-q '
                                                                                                                          '--queryformat '
                                                                                                                          "'%{VERSION}' "
                                                                                                                          'centos-release) '
                                                                                                                          '-eq '
                                                                                                                          '"7" '
                                                                                                                          '];\n'
                                                                                                                          '  '
                                                                                                                          'systemctl '
                                                                                                                          'stop '
                                                                                                                          'firewalld\n'
                                                                                                                          '  '
                                                                                                                          'systemctl '
                                                                                                                          'disable '
                                                                                                                          'firewalld\n'
                                                                                                                          'fi\n',
                                                                                                               'name': 'sh'},
                                                                                                  'name': 'Disable '
                                                                                                          'iptables '
                                                                                                          'firewall',
                                                                                                  'supported_platforms': ['linux']},
                                                                                                 {'auto_generated_guid': '88d05800-a5e4-407e-9b53-ece4174f197f',
                                                                                                  'description': 'Disables '
                                                                                                                 'the '
                                                                                                                 'Microsoft '
                                                                                                                 'Defender '
                                                                                                                 'Firewall '
                                                                                                                 'for '
                                                                                                                 'the '
                                                                                                                 'current '
                                                                                                                 'profile.\n'
                                                                                                                 'Caution '
                                                                                                                 'if '
                                                                                                                 'you '
                                                                                                                 'access '
                                                                                                                 'remotely '
                                                                                                                 'the '
                                                                                                                 'host '
                                                                                                                 'where '
                                                                                                                 'the '
                                                                                                                 'test '
                                                                                                                 'runs! '
                                                                                                                 'Especially '
                                                                                                                 'with '
                                                                                                                 'the '
                                                                                                                 'cleanup '
                                                                                                                 'command '
                                                                                                                 'which '
                                                                                                                 'will '
                                                                                                                 're-enable '
                                                                                                                 'firewall '
                                                                                                                 'for '
                                                                                                                 'the '
                                                                                                                 'current '
                                                                                                                 'profile...\n',
                                                                                                  'executor': {'cleanup_command': 'netsh '
                                                                                                                                  'advfirewall '
                                                                                                                                  'set '
                                                                                                                                  'currentprofile '
                                                                                                                                  'state '
                                                                                                                                  'on '
                                                                                                                                  '>nul '
                                                                                                                                  '2>&1\n',
                                                                                                               'command': 'netsh '
                                                                                                                          'advfirewall '
                                                                                                                          'set '
                                                                                                                          'currentprofile '
                                                                                                                          'state '
                                                                                                                          'off\n',
                                                                                                               'name': 'command_prompt'},
                                                                                                  'name': 'Disable '
                                                                                                          'Microsoft '
                                                                                                          'Defender '
                                                                                                          'Firewall',
                                                                                                  'supported_platforms': ['windows']},
                                                                                                 {'auto_generated_guid': 'd9841bf8-f161-4c73-81e9-fd773a5ff8c1',
                                                                                                  'description': 'Allow '
                                                                                                                 'all '
                                                                                                                 'SMB '
                                                                                                                 'and '
                                                                                                                 'RDP '
                                                                                                                 'rules '
                                                                                                                 'on '
                                                                                                                 'the '
                                                                                                                 'Microsoft '
                                                                                                                 'Defender '
                                                                                                                 'Firewall '
                                                                                                                 'for '
                                                                                                                 'all '
                                                                                                                 'profiles.\n'
                                                                                                                 'Caution '
                                                                                                                 'if '
                                                                                                                 'you '
                                                                                                                 'access '
                                                                                                                 'remotely '
                                                                                                                 'the '
                                                                                                                 'host '
                                                                                                                 'where '
                                                                                                                 'the '
                                                                                                                 'test '
                                                                                                                 'runs! '
                                                                                                                 'Especially '
                                                                                                                 'with '
                                                                                                                 'the '
                                                                                                                 'cleanup '
                                                                                                                 'command '
                                                                                                                 'which '
                                                                                                                 'will '
                                                                                                                 'reset '
                                                                                                                 'the '
                                                                                                                 'firewall '
                                                                                                                 'and '
                                                                                                                 'risk '
                                                                                                                 'disabling '
                                                                                                                 'those '
                                                                                                                 'services...\n',
                                                                                                  'executor': {'cleanup_command': 'netsh '
                                                                                                                                  'advfirewall '
                                                                                                                                  'reset '
                                                                                                                                  '>nul '
                                                                                                                                  '2>&1\n',
                                                                                                               'command': 'netsh '
                                                                                                                          'advfirewall '
                                                                                                                          'firewall '
                                                                                                                          'set '
                                                                                                                          'rule '
                                                                                                                          'group="remote '
                                                                                                                          'desktop" '
                                                                                                                          'new '
                                                                                                                          'enable=Yes\n'
                                                                                                                          'netsh '
                                                                                                                          'advfirewall '
                                                                                                                          'firewall '
                                                                                                                          'set '
                                                                                                                          'rule '
                                                                                                                          'group="file '
                                                                                                                          'and '
                                                                                                                          'printer '
                                                                                                                          'sharing" '
                                                                                                                          'new '
                                                                                                                          'enable=Yes\n',
                                                                                                               'name': 'command_prompt'},
                                                                                                  'name': 'Allow '
                                                                                                          'SMB '
                                                                                                          'and '
                                                                                                          'RDP '
                                                                                                          'on '
                                                                                                          'Microsoft '
                                                                                                          'Defender '
                                                                                                          'Firewall',
                                                                                                  'supported_platforms': ['windows']},
                                                                                                 {'auto_generated_guid': '15e57006-79dd-46df-9bf9-31bc24fb5a80',
                                                                                                  'description': 'This '
                                                                                                                 'test '
                                                                                                                 'creates '
                                                                                                                 'a '
                                                                                                                 'listening '
                                                                                                                 'interface '
                                                                                                                 'on '
                                                                                                                 'a '
                                                                                                                 'victim '
                                                                                                                 'device. '
                                                                                                                 'This '
                                                                                                                 'tactic '
                                                                                                                 'was '
                                                                                                                 'used '
                                                                                                                 'by '
                                                                                                                 'HARDRAIN '
                                                                                                                 'for '
                                                                                                                 'proxying.\n'
                                                                                                                 '\n'
                                                                                                                 'reference: '
                                                                                                                 'https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-F.pdf\n',
                                                                                                  'executor': {'cleanup_command': 'netsh '
                                                                                                                                  'advfirewall '
                                                                                                                                  'firewall '
                                                                                                                                  'delete '
                                                                                                                                  'rule '
                                                                                                                                  'name="atomic '
                                                                                                                                  'testing" '
                                                                                                                                  'protocol=TCP '
                                                                                                                                  'localport=450 '
                                                                                                                                  '>nul '
                                                                                                                                  '2>&1',
                                                                                                               'command': 'netsh '
                                                                                                                          'advfirewall '
                                                                                                                          'firewall '
                                                                                                                          'add '
                                                                                                                          'rule '
                                                                                                                          'name="atomic '
                                                                                                                          'testing" '
                                                                                                                          'action=allow '
                                                                                                                          'dir=in '
                                                                                                                          'protocol=TCP '
                                                                                                                          'localport=450 \n',
                                                                                                               'elevation_required': True,
                                                                                                               'name': 'command_prompt'},
                                                                                                  'name': 'Opening '
                                                                                                          'ports '
                                                                                                          'for '
                                                                                                          'proxy '
                                                                                                          '- '
                                                                                                          'HARDRAIN',
                                                                                                  'supported_platforms': ['windows']},
                                                                                                 {'auto_generated_guid': '9636dd6e-7599-40d2-8eee-ac16434f35ed',
                                                                                                  'description': 'This '
                                                                                                                 'test '
                                                                                                                 'will '
                                                                                                                 'attempt '
                                                                                                                 'to '
                                                                                                                 'open '
                                                                                                                 'a '
                                                                                                                 'local '
                                                                                                                 'port '
                                                                                                                 'defined '
                                                                                                                 'by '
                                                                                                                 'input '
                                                                                                                 'arguments '
                                                                                                                 'to '
                                                                                                                 'any '
                                                                                                                 'profile',
                                                                                                  'executor': {'cleanup_command': 'netsh '
                                                                                                                                  'advfirewall '
                                                                                                                                  'firewall '
                                                                                                                                  'delete '
                                                                                                                                  'rule '
                                                                                                                                  'name="Open '
                                                                                                                                  'Port '
                                                                                                                                  'to '
                                                                                                                                  'Any"',
                                                                                                               'command': 'netsh '
                                                                                                                          'advfirewall '
                                                                                                                          'firewall '
                                                                                                                          'add '
                                                                                                                          'rule '
                                                                                                                          'name="Open '
                                                                                                                          'Port '
                                                                                                                          'to '
                                                                                                                          'Any" '
                                                                                                                          'dir=in '
                                                                                                                          'protocol=tcp '
                                                                                                                          'localport=#{local_port} '
                                                                                                                          'action=allow '
                                                                                                                          'profile=any',
                                                                                                               'elevation_required': True,
                                                                                                               'name': 'powershell'},
                                                                                                  'input_arguments': {'local_port': {'default': 3389,
                                                                                                                                     'description': 'This '
                                                                                                                                                    'is '
                                                                                                                                                    'the '
                                                                                                                                                    'local '
                                                                                                                                                    'port '
                                                                                                                                                    'you '
                                                                                                                                                    'wish '
                                                                                                                                                    'to '
                                                                                                                                                    'test '
                                                                                                                                                    'opening',
                                                                                                                                     'type': 'integer'}},
                                                                                                  'name': 'Open '
                                                                                                          'a '
                                                                                                          'local '
                                                                                                          'port '
                                                                                                          'through '
                                                                                                          'Windows '
                                                                                                          'Firewall '
                                                                                                          'to '
                                                                                                          'any '
                                                                                                          'profile',
                                                                                                  'supported_platforms': ['windows']},
                                                                                                 {'auto_generated_guid': '6f5822d2-d38d-4f48-9bfc-916607ff6b8c',
                                                                                                  'dependencies': [{'description': 'exe '
                                                                                                                                   'file '
                                                                                                                                   'must '
                                                                                                                                   'exist '
                                                                                                                                   'on '
                                                                                                                                   'disk '
                                                                                                                                   'in '
                                                                                                                                   'users '
                                                                                                                                   'folder\n',
                                                                                                                    'get_prereq_command': 'Copy-Item '
                                                                                                                                          '#{exe_file_path} '
                                                                                                                                          '-Destination '
                                                                                                                                          '"C:\\Users\\$env:UserName"\n',
                                                                                                                    'prereq_command': 'if '
                                                                                                                                      '(Get-Item '
                                                                                                                                      '"C:\\Users\\$env:UserName\\AtomicTest.exe") '
                                                                                                                                      '{exit '
                                                                                                                                      '0} '
                                                                                                                                      'else '
                                                                                                                                      '{exit '
                                                                                                                                      '1}\n'}],
                                                                                                  'dependency_executor_name': 'powershell',
                                                                                                  'description': 'This '
                                                                                                                 'test '
                                                                                                                 'will '
                                                                                                                 'attempt '
                                                                                                                 'to '
                                                                                                                 'allow '
                                                                                                                 'an '
                                                                                                                 'executable '
                                                                                                                 'through '
                                                                                                                 'the '
                                                                                                                 'system '
                                                                                                                 'firewall '
                                                                                                                 'located '
                                                                                                                 'in '
                                                                                                                 'the '
                                                                                                                 'Users '
                                                                                                                 'directory',
                                                                                                  'executor': {'cleanup_command': 'netsh '
                                                                                                                                  'advfirewall '
                                                                                                                                  'firewall '
                                                                                                                                  'delete '
                                                                                                                                  'rule '
                                                                                                                                  'name="Atomic '
                                                                                                                                  'Test"',
                                                                                                               'command': 'netsh '
                                                                                                                          'advfirewall '
                                                                                                                          'firewall '
                                                                                                                          'add '
                                                                                                                          'rule '
                                                                                                                          'name="Atomic '
                                                                                                                          'Test" '
                                                                                                                          'dir=in '
                                                                                                                          'action=allow '
                                                                                                                          'program="C:\\Users\\$env:UserName\\AtomicTest.exe" '
                                                                                                                          'enable=yes',
                                                                                                               'elevation_required': True,
                                                                                                               'name': 'powershell'},
                                                                                                  'input_arguments': {'exe_file_path': {'default': 'PathToAtomicsFolder\\T1562.004\\bin\\AtomicTest.exe',
                                                                                                                                        'description': 'path '
                                                                                                                                                       'to '
                                                                                                                                                       'exe '
                                                                                                                                                       'file',
                                                                                                                                        'type': 'path'}},
                                                                                                  'name': 'Allow '
                                                                                                          'Executable '
                                                                                                          'Through '
                                                                                                          'Firewall '
                                                                                                          'Located '
                                                                                                          'in '
                                                                                                          'Non-Standard '
                                                                                                          'Location',
                                                                                                  'supported_platforms': ['windows']}],
                                                                                'attack_technique': 'T1562.004',
                                                                                'display_name': 'Impair '
                                                                                                'Defenses: '
                                                                                                'Disable '
                                                                                                'or '
                                                                                                'Modify '
                                                                                                'System '
                                                                                                'Firewall'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [User Account Management](../mitigations/User-Account-Management.md)

* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)
    
* [Restrict Registry Permissions](../mitigations/Restrict-Registry-Permissions.md)
    

# Actors


* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)

* [Carbanak](../actors/Carbanak.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Rocke](../actors/Rocke.md)
    
