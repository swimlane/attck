
# Modify Registry

## Description

### MITRE Description

> Adversaries may interact with the Windows Registry to hide configuration information within Registry keys, remove information as part of cleaning up, or as part of other techniques to aid in Persistence and Execution.

Access to specific areas of the Registry depends on account permissions, some requiring administrator-level access. The built-in Windows command-line utility [Reg](https://attack.mitre.org/software/S0075) may be used for local or remote Registry modification. (Citation: Microsoft Reg) Other tools may also be used, such as a remote access tool, which may contain functionality to interact with the Registry through the Windows API (see examples).

Registry modifications may also include actions to hide keys, such as prepending key names with a null character, which will cause an error and/or be ignored when read via [Reg](https://attack.mitre.org/software/S0075) or other utilities using the Win32 API. (Citation: Microsoft Reghide NOV 2006) Adversaries may abuse these pseudo-hidden keys to conceal payloads/commands used to establish Persistence. (Citation: TrendMicro POWELIKS AUG 2014) (Citation: SpectorOps Hiding Reg Jul 2017)

The Registry of a remote system may be modified to aid in execution of files as part of Lateral Movement. It requires the remote Registry service to be running on the target system. (Citation: Microsoft Remote) Often [Valid Accounts](https://attack.mitre.org/techniques/T1078) are required, along with access to the remote system's [Windows Admin Shares](https://attack.mitre.org/techniques/T1077) for RPC communication.

## Additional Attributes

* Bypass: ['Host forensic analysis']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1112

## Potential Commands

```
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /t REG_DWORD /v HideFileExt /d 1 /f

reg add HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run /t REG_EXPAND_SZ /v SecurityHealth /d calc.exe /f

reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f

$key= "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\bad-domain.com\"
$name ="bad-subdomain"
new-item $key -Name $name -Force
new-itemproperty $key$name -Name https -Value 2 -Type DWORD;
new-itemproperty $key$name -Name http  -Value 2 -Type DWORD;
new-itemproperty $key$name -Name *     -Value 2 -Type DWORD;

New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name T1112 -Value "<script>"

powershell/persistence/misc/disable_machine_acct_change
powershell/persistence/misc/disable_machine_acct_change
```

## Commands Dataset

```
[{'command': 'reg add '
             'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced '
             '/t REG_DWORD /v HideFileExt /d 1 /f\n',
  'name': None,
  'source': 'atomics/T1112/T1112.yaml'},
 {'command': 'reg add '
             'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
             '/t REG_EXPAND_SZ /v SecurityHealth /d calc.exe /f\n',
  'name': None,
  'source': 'atomics/T1112/T1112.yaml'},
 {'command': 'reg add '
             'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest '
             '/v UseLogonCredential /t REG_DWORD /d 1 /f\n',
  'name': None,
  'source': 'atomics/T1112/T1112.yaml'},
 {'command': '$key= '
             '"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet '
             'Settings\\ZoneMap\\Domains\\bad-domain.com\\"\n'
             '$name ="bad-subdomain"\n'
             'new-item $key -Name $name -Force\n'
             'new-itemproperty $key$name -Name https -Value 2 -Type DWORD;\n'
             'new-itemproperty $key$name -Name http  -Value 2 -Type DWORD;\n'
             'new-itemproperty $key$name -Name *     -Value 2 -Type DWORD;\n',
  'name': None,
  'source': 'atomics/T1112/T1112.yaml'},
 {'command': 'New-ItemProperty '
             '"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet '
             'Settings" -Name T1112 -Value "<script>"\n',
  'name': None,
  'source': 'atomics/T1112/T1112.yaml'},
 {'command': 'powershell/persistence/misc/disable_machine_acct_change',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/misc/disable_machine_acct_change',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Modify Registry',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where process_path contains "reg.exe"and file_directory '
           'contains "reg.exe\\" query"'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Modify Registry': {'atomic_tests': [{'description': 'Modify '
                                                                              'the '
                                                                              'registry '
                                                                              'of '
                                                                              'the '
                                                                              'currently '
                                                                              'logged '
                                                                              'in '
                                                                              'user '
                                                                              'using '
                                                                              'reg.exe '
                                                                              'via '
                                                                              'cmd '
                                                                              'console. '
                                                                              'Upon '
                                                                              'execution, '
                                                                              'the '
                                                                              'message '
                                                                              '"The '
                                                                              'operation '
                                                                              'completed '
                                                                              'successfully."\n'
                                                                              'will '
                                                                              'be '
                                                                              'displayed. '
                                                                              'Additionally, '
                                                                              'open '
                                                                              'Registry '
                                                                              'Editor '
                                                                              'to '
                                                                              'view '
                                                                              'the '
                                                                              'new '
                                                                              'entry '
                                                                              'in '
                                                                              'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced.\n',
                                                               'executor': {'cleanup_command': 'reg '
                                                                                               'delete '
                                                                                               'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced '
                                                                                               '/v '
                                                                                               'HideFileExt '
                                                                                               '/f '
                                                                                               '>nul '
                                                                                               '2>&1\n',
                                                                            'command': 'reg '
                                                                                       'add '
                                                                                       'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced '
                                                                                       '/t '
                                                                                       'REG_DWORD '
                                                                                       '/v '
                                                                                       'HideFileExt '
                                                                                       '/d '
                                                                                       '1 '
                                                                                       '/f\n',
                                                                            'elevation_required': True,
                                                                            'name': 'command_prompt'},
                                                               'name': 'Modify '
                                                                       'Registry '
                                                                       'of '
                                                                       'Current '
                                                                       'User '
                                                                       'Profile '
                                                                       '- cmd',
                                                               'supported_platforms': ['windows']},
                                                              {'description': 'Modify '
                                                                              'the '
                                                                              'Local '
                                                                              'Machine '
                                                                              'registry '
                                                                              'RUN '
                                                                              'key '
                                                                              'to '
                                                                              'change '
                                                                              'Windows '
                                                                              'Defender '
                                                                              'executable '
                                                                              'that '
                                                                              'should '
                                                                              'be '
                                                                              'ran '
                                                                              'on '
                                                                              'startup.  '
                                                                              'This '
                                                                              'should '
                                                                              'only '
                                                                              'be '
                                                                              'possible '
                                                                              'when\n'
                                                                              'CMD '
                                                                              'is '
                                                                              'ran '
                                                                              'as '
                                                                              'Administrative '
                                                                              'rights. '
                                                                              'Upon '
                                                                              'execution, '
                                                                              'the '
                                                                              'message '
                                                                              '"The '
                                                                              'operation '
                                                                              'completed '
                                                                              'successfully."\n'
                                                                              'will '
                                                                              'be '
                                                                              'displayed. '
                                                                              'Additionally, '
                                                                              'open '
                                                                              'Registry '
                                                                              'Editor '
                                                                              'to '
                                                                              'view '
                                                                              'the '
                                                                              'modified '
                                                                              'entry '
                                                                              'in '
                                                                              'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run.\n',
                                                               'executor': {'cleanup_command': 'reg '
                                                                                               'delete '
                                                                                               'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                                                                                               '/v '
                                                                                               'SecurityHealth '
                                                                                               '/f '
                                                                                               '>nul '
                                                                                               '2>&1\n',
                                                                            'command': 'reg '
                                                                                       'add '
                                                                                       'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run '
                                                                                       '/t '
                                                                                       'REG_EXPAND_SZ '
                                                                                       '/v '
                                                                                       'SecurityHealth '
                                                                                       '/d '
                                                                                       '#{new_executable} '
                                                                                       '/f\n',
                                                                            'elevation_required': True,
                                                                            'name': 'command_prompt'},
                                                               'input_arguments': {'new_executable': {'default': 'calc.exe',
                                                                                                      'description': 'New '
                                                                                                                     'executable '
                                                                                                                     'to '
                                                                                                                     'run '
                                                                                                                     'on '
                                                                                                                     'startup '
                                                                                                                     'instead '
                                                                                                                     'of '
                                                                                                                     'Windows '
                                                                                                                     'Defender',
                                                                                                      'type': 'string'}},
                                                               'name': 'Modify '
                                                                       'Registry '
                                                                       'of '
                                                                       'Local '
                                                                       'Machine '
                                                                       '- cmd',
                                                               'supported_platforms': ['windows']},
                                                              {'description': 'Sets '
                                                                              'registry '
                                                                              'key '
                                                                              'that '
                                                                              'will '
                                                                              'tell '
                                                                              'windows '
                                                                              'to '
                                                                              'store '
                                                                              'plaintext '
                                                                              'passwords '
                                                                              '(making '
                                                                              'the '
                                                                              'system '
                                                                              'vulnerable '
                                                                              'to '
                                                                              'clear '
                                                                              'text '
                                                                              '/ '
                                                                              'cleartext '
                                                                              'password '
                                                                              'dumping).\n'
                                                                              'Upon '
                                                                              'execution, '
                                                                              'the '
                                                                              'message '
                                                                              '"The '
                                                                              'operation '
                                                                              'completed '
                                                                              'successfully." '
                                                                              'will '
                                                                              'be '
                                                                              'displayed.\n'
                                                                              'Additionally, '
                                                                              'open '
                                                                              'Registry '
                                                                              'Editor '
                                                                              'to '
                                                                              'view '
                                                                              'the '
                                                                              'modified '
                                                                              'entry '
                                                                              'in '
                                                                              'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest.\n',
                                                               'executor': {'cleanup_command': 'reg '
                                                                                               'add '
                                                                                               'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest '
                                                                                               '/v '
                                                                                               'UseLogonCredential '
                                                                                               '/t '
                                                                                               'REG_DWORD '
                                                                                               '/d '
                                                                                               '0 '
                                                                                               '/f '
                                                                                               '>nul '
                                                                                               '2>&1\n',
                                                                            'command': 'reg '
                                                                                       'add '
                                                                                       'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest '
                                                                                       '/v '
                                                                                       'UseLogonCredential '
                                                                                       '/t '
                                                                                       'REG_DWORD '
                                                                                       '/d '
                                                                                       '1 '
                                                                                       '/f\n',
                                                                            'elevation_required': True,
                                                                            'name': 'command_prompt'},
                                                               'name': 'Modify '
                                                                       'registry '
                                                                       'to '
                                                                       'store '
                                                                       'logon '
                                                                       'credentials',
                                                               'supported_platforms': ['windows']},
                                                              {'description': 'Attackers '
                                                                              'may '
                                                                              'add '
                                                                              'a '
                                                                              'domain '
                                                                              'to '
                                                                              'the '
                                                                              'trusted '
                                                                              'site '
                                                                              'zone '
                                                                              'to '
                                                                              'bypass '
                                                                              'defenses. '
                                                                              'Doing '
                                                                              'this '
                                                                              'enables '
                                                                              'attacks '
                                                                              'such '
                                                                              'as '
                                                                              'c2 '
                                                                              'over '
                                                                              'office365.\n'
                                                                              'Upon '
                                                                              'execution, '
                                                                              'details '
                                                                              'of '
                                                                              'the '
                                                                              'new '
                                                                              'registry '
                                                                              'entries '
                                                                              'will '
                                                                              'be '
                                                                              'displayed.\n'
                                                                              'Additionally, '
                                                                              'open '
                                                                              'Registry '
                                                                              'Editor '
                                                                              'to '
                                                                              'view '
                                                                              'the '
                                                                              'modified '
                                                                              'entry '
                                                                              'in '
                                                                              'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet '
                                                                              'Settings\\ZoneMap\\.\n'
                                                                              '\n'
                                                                              'https://www.blackhat.com/docs/us-17/wednesday/us-17-Dods-Infecting-The-Enterprise-Abusing-Office365-Powershell-For-Covert-C2.pdf\n',
                                                               'executor': {'cleanup_command': '$key '
                                                                                               '= '
                                                                                               '"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet '
                                                                                               'Settings\\ZoneMap\\Domains\\#{bad_domain}\\"\n'
                                                                                               'Remove-item  '
                                                                                               '$key '
                                                                                               '-Recurse '
                                                                                               '-ErrorAction '
                                                                                               'Ignore\n',
                                                                            'command': '$key= '
                                                                                       '"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet '
                                                                                       'Settings\\ZoneMap\\Domains\\#{bad_domain}\\"\n'
                                                                                       '$name '
                                                                                       '="bad-subdomain"\n'
                                                                                       'new-item '
                                                                                       '$key '
                                                                                       '-Name '
                                                                                       '$name '
                                                                                       '-Force\n'
                                                                                       'new-itemproperty '
                                                                                       '$key$name '
                                                                                       '-Name '
                                                                                       'https '
                                                                                       '-Value '
                                                                                       '2 '
                                                                                       '-Type '
                                                                                       'DWORD;\n'
                                                                                       'new-itemproperty '
                                                                                       '$key$name '
                                                                                       '-Name '
                                                                                       'http  '
                                                                                       '-Value '
                                                                                       '2 '
                                                                                       '-Type '
                                                                                       'DWORD;\n'
                                                                                       'new-itemproperty '
                                                                                       '$key$name '
                                                                                       '-Name '
                                                                                       '*     '
                                                                                       '-Value '
                                                                                       '2 '
                                                                                       '-Type '
                                                                                       'DWORD;\n',
                                                                            'elevation_required': False,
                                                                            'name': 'powershell'},
                                                               'input_arguments': {'bad_domain': {'default': 'bad-domain.com',
                                                                                                  'description': 'Domain '
                                                                                                                 'to '
                                                                                                                 'add '
                                                                                                                 'to '
                                                                                                                 'trusted '
                                                                                                                 'site '
                                                                                                                 'zone',
                                                                                                  'type': 'String'}},
                                                               'name': 'Add '
                                                                       'domain '
                                                                       'to '
                                                                       'Trusted '
                                                                       'sites '
                                                                       'Zone',
                                                               'supported_platforms': ['windows']},
                                                              {'description': 'Upon '
                                                                              'execution, '
                                                                              'a '
                                                                              'javascript '
                                                                              'block '
                                                                              'will '
                                                                              'be '
                                                                              'placed '
                                                                              'in '
                                                                              'the '
                                                                              'registry '
                                                                              'for '
                                                                              'persistence.\n'
                                                                              'Additionally, '
                                                                              'open '
                                                                              'Registry '
                                                                              'Editor '
                                                                              'to '
                                                                              'view '
                                                                              'the '
                                                                              'modified '
                                                                              'entry '
                                                                              'in '
                                                                              'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet '
                                                                              'Settings.\n',
                                                               'executor': {'cleanup_command': 'Remove-ItemProperty '
                                                                                               '"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet '
                                                                                               'Settings" '
                                                                                               '-Name '
                                                                                               'T1112 '
                                                                                               '-ErrorAction '
                                                                                               'Ignore\n',
                                                                            'command': 'New-ItemProperty '
                                                                                       '"HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet '
                                                                                       'Settings" '
                                                                                       '-Name '
                                                                                       'T1112 '
                                                                                       '-Value '
                                                                                       '"<script>"\n',
                                                                            'elevation_required': False,
                                                                            'name': 'powershell'},
                                                               'name': 'Javascript '
                                                                       'in '
                                                                       'registry',
                                                               'supported_platforms': ['windows']}],
                                             'attack_technique': 'T1112',
                                             'display_name': 'Modify '
                                                             'Registry'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1112',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/persistence/misc/disable_machine_acct_change":  '
                                                                                 '["T1112"],',
                                            'Empire Module': 'powershell/persistence/misc/disable_machine_acct_change',
                                            'Technique': 'Modify Registry'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors


* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)

* [APT19](../actors/APT19.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [APT38](../actors/APT38.md)
    
* [Honeybee](../actors/Honeybee.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [FIN8](../actors/FIN8.md)
    
* [Gorgon Group](../actors/Gorgon-Group.md)
    
* [APT32](../actors/APT32.md)
    
* [Turla](../actors/Turla.md)
    
* [APT41](../actors/APT41.md)
    
