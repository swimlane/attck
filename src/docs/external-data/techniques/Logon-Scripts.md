
# Logon Scripts

## Description

### MITRE Description

> ### Windows

Windows allows logon scripts to be run whenever a specific user or group of users log into a system. (Citation: TechNet Logon Scripts) The scripts can be used to perform administrative functions, which may often execute other programs or send information to an internal logging server.

If adversaries can access these scripts, they may insert additional code into the logon script to execute their tools when a user logs in. This code can allow them to maintain persistence on a single system, if it is a local script, or to move laterally within a network, if the script is stored on a central server and pushed to many systems. Depending on the access configuration of the logon scripts, either local credentials or an administrator account may be necessary.

### Mac

Mac allows login and logoff hooks to be run as root whenever a specific user logs into or out of a system. A login hook tells Mac OS X to execute a certain script when a user logs in, but unlike startup items, a login hook executes as root (Citation: creating login hook). There can only be one login hook at a time though. If adversaries can access these scripts, they can insert additional code to the script to execute their tools when a user logs in.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: None
* Platforms: ['macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1037

## Potential Commands

```
echo "#{script_command}" > %temp%\art.bat
REG.exe ADD HKCU\Environment /v UserInitMprLogonScript /t REG_SZ /d "%temp%\art.bat" /f

echo "echo Art "Logon Script" atomic test was successful. >> %USERPROFILE%\desktop\T1037-log.txt" > #{script_path}
REG.exe ADD HKCU\Environment /v UserInitMprLogonScript /t REG_SZ /d "#{script_path}" /f

schtasks /create /tn "T1037_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"
schtasks /create /tn "T1037_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"

Copy-Item $PathToAtomicsFolder\T1037\src\vbsstartup.vbs "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\vbsstartup.vbs"
Copy-Item $PathToAtomicsFolder\T1037\src\vbsstartup.vbs "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\vbsstartup.vbs"
cscript.exe "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\vbsstartup.vbs"
cscript.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\vbsstartup.vbs"

Copy-Item $PathToAtomicsFolder\T1037\src\jsestartup.jse "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse"
Copy-Item $PathToAtomicsFolder\T1037\src\jsestartup.jse "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\jsestartup.jse"
cscript.exe /E:Jscript "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\jsestartup.jse"
cscript.exe /E:Jscript "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\jsestartup.jse"

Copy-Item $PathToAtomicsFolder\T1037\src\batstartup.bat "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat"
Copy-Item $PathToAtomicsFolder\T1037\src\batstartup.bat "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\batstartup.bat"
Start-Process "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\batstartup.bat"
Start-Process "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\batstartup.bat"

\Environment\UserInitMprLogonScript
\Environment\UserInitMprLogonScript
python/persistence/multi/desktopfile
python/persistence/multi/desktopfile
python/persistence/osx/loginhook
python/persistence/osx/loginhook
```

## Commands Dataset

```
[{'command': 'echo "#{script_command}" > %temp%\\art.bat\n'
             'REG.exe ADD HKCU\\Environment /v UserInitMprLogonScript /t '
             'REG_SZ /d "%temp%\\art.bat" /f\n',
  'name': None,
  'source': 'atomics/T1037/T1037.yaml'},
 {'command': 'echo "echo Art "Logon Script" atomic test was successful. >> '
             '%USERPROFILE%\\desktop\\T1037-log.txt" > #{script_path}\n'
             'REG.exe ADD HKCU\\Environment /v UserInitMprLogonScript /t '
             'REG_SZ /d "#{script_path}" /f\n',
  'name': None,
  'source': 'atomics/T1037/T1037.yaml'},
 {'command': 'schtasks /create /tn "T1037_OnLogon" /sc onlogon /tr "cmd.exe /c '
             'calc.exe"\n'
             'schtasks /create /tn "T1037_OnStartup" /sc onstart /ru system '
             '/tr "cmd.exe /c calc.exe"\n',
  'name': None,
  'source': 'atomics/T1037/T1037.yaml'},
 {'command': 'Copy-Item $PathToAtomicsFolder\\T1037\\src\\vbsstartup.vbs '
             '"$env:APPDATA\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup\\vbsstartup.vbs"\n'
             'Copy-Item $PathToAtomicsFolder\\T1037\\src\\vbsstartup.vbs '
             '"C:\\ProgramData\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\StartUp\\vbsstartup.vbs"\n'
             'cscript.exe "$env:APPDATA\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup\\vbsstartup.vbs"\n'
             'cscript.exe "C:\\ProgramData\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\StartUp\\vbsstartup.vbs"\n',
  'name': None,
  'source': 'atomics/T1037/T1037.yaml'},
 {'command': 'Copy-Item $PathToAtomicsFolder\\T1037\\src\\jsestartup.jse '
             '"$env:APPDATA\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup\\jsestartup.jse"\n'
             'Copy-Item $PathToAtomicsFolder\\T1037\\src\\jsestartup.jse '
             '"C:\\ProgramData\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\StartUp\\jsestartup.jse"\n'
             'cscript.exe /E:Jscript "$env:APPDATA\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup\\jsestartup.jse"\n'
             'cscript.exe /E:Jscript '
             '"C:\\ProgramData\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\StartUp\\jsestartup.jse"\n',
  'name': None,
  'source': 'atomics/T1037/T1037.yaml'},
 {'command': 'Copy-Item $PathToAtomicsFolder\\T1037\\src\\batstartup.bat '
             '"$env:APPDATA\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup\\batstartup.bat"\n'
             'Copy-Item $PathToAtomicsFolder\\T1037\\src\\batstartup.bat '
             '"C:\\ProgramData\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\StartUp\\batstartup.bat"\n'
             'Start-Process "$env:APPDATA\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup\\batstartup.bat"\n'
             'Start-Process "C:\\ProgramData\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\StartUp\\batstartup.bat"\n',
  'name': None,
  'source': 'atomics/T1037/T1037.yaml'},
 {'command': '\\Environment\\UserInitMprLogonScript',
  'name': None,
  'source': 'SysmonHunter - Logon Scripts'},
 {'command': '\\Environment\\UserInitMprLogonScript',
  'name': None,
  'source': 'SysmonHunter - Logon Scripts'},
 {'command': 'python/persistence/multi/desktopfile',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/persistence/multi/desktopfile',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/persistence/osx/loginhook',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/persistence/osx/loginhook',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Logon Scripts',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and process_command_line contains '
           '"*REG*ADD*HKCU\\\\Environment*UserInitMprLogonScript*"'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Logon Scripts': {'atomic_tests': [{'description': 'Adds '
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
                                                                                             '"%USERPROFILE%\\desktop\\T1037-log.txt" '
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
                                                                          'elevation_required': False,
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
                                                                                                               '%USERPROFILE%\\desktop\\T1037-log.txt',
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
                                                             'supported_platforms': ['windows']},
                                                            {'description': 'Run '
                                                                            'an '
                                                                            'exe '
                                                                            'on '
                                                                            'user '
                                                                            'logon '
                                                                            'or '
                                                                            'system '
                                                                            'startup.  '
                                                                            'Upon '
                                                                            'execution, '
                                                                            'success '
                                                                            'messages '
                                                                            'will '
                                                                            'be '
                                                                            'displayed '
                                                                            'for '
                                                                            'the '
                                                                            'two '
                                                                            'scheduled '
                                                                            'tasks. '
                                                                            'To '
                                                                            'view\n'
                                                                            'the '
                                                                            'tasks, '
                                                                            'open '
                                                                            'the '
                                                                            'Task '
                                                                            'Scheduler '
                                                                            'and '
                                                                            'look '
                                                                            'in '
                                                                            'the '
                                                                            'Active '
                                                                            'Tasks '
                                                                            'pane.\n',
                                                             'executor': {'cleanup_command': 'schtasks '
                                                                                             '/delete '
                                                                                             '/tn '
                                                                                             '"T1037_OnLogon" '
                                                                                             '/f '
                                                                                             '>nul '
                                                                                             '2>&1\n'
                                                                                             'schtasks '
                                                                                             '/delete '
                                                                                             '/tn '
                                                                                             '"T1037_OnStartup" '
                                                                                             '/f '
                                                                                             '>nul '
                                                                                             '2>&1\n',
                                                                          'command': 'schtasks '
                                                                                     '/create '
                                                                                     '/tn '
                                                                                     '"T1037_OnLogon" '
                                                                                     '/sc '
                                                                                     'onlogon '
                                                                                     '/tr '
                                                                                     '"cmd.exe '
                                                                                     '/c '
                                                                                     'calc.exe"\n'
                                                                                     'schtasks '
                                                                                     '/create '
                                                                                     '/tn '
                                                                                     '"T1037_OnStartup" '
                                                                                     '/sc '
                                                                                     'onstart '
                                                                                     '/ru '
                                                                                     'system '
                                                                                     '/tr '
                                                                                     '"cmd.exe '
                                                                                     '/c '
                                                                                     'calc.exe"\n',
                                                                          'elevation_required': True,
                                                                          'name': 'command_prompt'},
                                                             'name': 'Scheduled '
                                                                     'Task '
                                                                     'Startup '
                                                                     'Script',
                                                             'supported_platforms': ['windows']},
                                                            {'description': 'Mac '
                                                                            'logon '
                                                                            'script\n',
                                                             'executor': {'name': 'manual',
                                                                          'steps': '1. '
                                                                                   'Create '
                                                                                   'the '
                                                                                   'required '
                                                                                   'plist '
                                                                                   'file\n'
                                                                                   '\n'
                                                                                   '    '
                                                                                   'sudo '
                                                                                   'touch '
                                                                                   '/private/var/root/Library/Preferences/com.apple.loginwindow.plist\n'
                                                                                   '\n'
                                                                                   '2. '
                                                                                   'Populate '
                                                                                   'the '
                                                                                   'plist '
                                                                                   'with '
                                                                                   'the '
                                                                                   'location '
                                                                                   'of '
                                                                                   'your '
                                                                                   'shell '
                                                                                   'script\n'
                                                                                   '\n'
                                                                                   '    '
                                                                                   'sudo '
                                                                                   'defaults '
                                                                                   'write '
                                                                                   'com.apple.loginwindow '
                                                                                   'LoginHook '
                                                                                   '/Library/Scripts/AtomicRedTeam.sh\n'
                                                                                   '\n'
                                                                                   '3. '
                                                                                   'Create '
                                                                                   'the '
                                                                                   'required '
                                                                                   'plist '
                                                                                   'file '
                                                                                   'in '
                                                                                   'the '
                                                                                   'target '
                                                                                   "user's "
                                                                                   'Preferences '
                                                                                   'directory\n'
                                                                                   '\n'
                                                                                   '\t  '
                                                                                   'touch '
                                                                                   '/Users/$USER/Library/Preferences/com.apple.loginwindow.plist\n'
                                                                                   '\n'
                                                                                   '4. '
                                                                                   'Populate '
                                                                                   'the '
                                                                                   'plist '
                                                                                   'with '
                                                                                   'the '
                                                                                   'location '
                                                                                   'of '
                                                                                   'your '
                                                                                   'shell '
                                                                                   'script\n'
                                                                                   '\n'
                                                                                   '\t  '
                                                                                   'defaults '
                                                                                   'write '
                                                                                   'com.apple.loginwindow '
                                                                                   'LoginHook '
                                                                                   '/Library/Scripts/AtomicRedTeam.sh\n'},
                                                             'name': 'Logon '
                                                                     'Scripts '
                                                                     '- Mac',
                                                             'supported_platforms': ['macos']},
                                                            {'description': 'vbs '
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
                                                                            '"T1137 '
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
                                                                                     '$PathToAtomicsFolder\\T1037\\src\\vbsstartup.vbs '
                                                                                     '"$env:APPDATA\\Microsoft\\Windows\\Start '
                                                                                     'Menu\\Programs\\Startup\\vbsstartup.vbs"\n'
                                                                                     'Copy-Item '
                                                                                     '$PathToAtomicsFolder\\T1037\\src\\vbsstartup.vbs '
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
                                                             'name': 'Supicious '
                                                                     'vbs file '
                                                                     'run from '
                                                                     'startup '
                                                                     'Folder',
                                                             'supported_platforms': ['windows']},
                                                            {'description': 'jse '
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
                                                                            '"T1137 '
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
                                                                                     '$PathToAtomicsFolder\\T1037\\src\\jsestartup.jse '
                                                                                     '"$env:APPDATA\\Microsoft\\Windows\\Start '
                                                                                     'Menu\\Programs\\Startup\\jsestartup.jse"\n'
                                                                                     'Copy-Item '
                                                                                     '$PathToAtomicsFolder\\T1037\\src\\jsestartup.jse '
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
                                                             'name': 'Supicious '
                                                                     'jse file '
                                                                     'run from '
                                                                     'startup '
                                                                     'Folder',
                                                             'supported_platforms': ['windows']},
                                                            {'description': 'bat '
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
                                                                                     '$PathToAtomicsFolder\\T1037\\src\\batstartup.bat '
                                                                                     '"$env:APPDATA\\Microsoft\\Windows\\Start '
                                                                                     'Menu\\Programs\\Startup\\batstartup.bat"\n'
                                                                                     'Copy-Item '
                                                                                     '$PathToAtomicsFolder\\T1037\\src\\batstartup.bat '
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
                                                             'name': 'Supicious '
                                                                     'bat file '
                                                                     'run from '
                                                                     'startup '
                                                                     'Folder',
                                                             'supported_platforms': ['windows']}],
                                           'attack_technique': 'T1037',
                                           'display_name': 'Logon Scripts'}},
 {'SysmonHunter - T1037': {'description': None,
                           'level': 'medium',
                           'name': 'Logon Scripts',
                           'phase': 'Persistence',
                           'query': [{'process': {'cmdline': {'pattern': '\\Environment\\UserInitMprLogonScript'}},
                                      'type': 'process'},
                                     {'reg': {'path': {'pattern': '\\Environment\\UserInitMprLogonScript'}},
                                      'type': 'reg'}]}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1037',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/persistence/multi/desktopfile":  '
                                                                                 '["T1037"],',
                                            'Empire Module': 'python/persistence/multi/desktopfile',
                                            'Technique': 'Logon Scripts'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1037',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/persistence/osx/loginhook":  '
                                                                                 '["T1037"],',
                                            'Empire Module': 'python/persistence/osx/loginhook',
                                            'Technique': 'Logon Scripts'}}]
```

# Tactics


* [Lateral Movement](../tactics/Lateral-Movement.md)

* [Persistence](../tactics/Persistence.md)
    

# Mitigations

None

# Actors


* [APT28](../actors/APT28.md)

* [Cobalt Group](../actors/Cobalt-Group.md)
    
