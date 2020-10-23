
# Rename System Utilities

## Description

### MITRE Description

> Adversaries may rename legitimate system utilities to try to evade security mechanisms concerning the usage of those utilities. Security monitoring and control mechanisms may be in place for system utilities adversaries are capable of abusing. (Citation: LOLBAS Main Site) It may be possible to bypass those security mechanisms by renaming the utility prior to utilization (ex: rename <code>rundll32.exe</code>). (Citation: Endgame Masquerade Ball) An alternative case occurs when a legitimate utility is copied or moved to a different directory and renamed to avoid detections based on system utilities executing from non-standard paths. (Citation: F-Secure CozyDuke)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1036/003

## Potential Commands

```
cp /bin/sh /tmp/crond;
/tmp/crond
copy #{exe_path} %temp%\T1036.003_masquerading.docx.exe /Y
copy #{exe_path} %temp%\T1036.003_masquerading.pdf.exe /Y
copy #{exe_path} %temp%\T1036.003_masquerading.ps1.exe /Y
copy PathToAtomicsFolder\T1036.003\src\T1036.003_masquerading.vbs %temp%\T1036.003_masquerading.xls.vbs /Y
copy PathToAtomicsFolder\T1036.003\src\T1036.003_masquerading.vbs %temp%\T1036.003_masquerading.xlsx.vbs /Y
copy PathToAtomicsFolder\T1036.003\src\T1036.003_masquerading.vbs %temp%\T1036.003_masquerading.png.vbs /Y
copy #{ps1_path} %temp%\T1036.003_masquerading.doc.ps1 /Y
copy #{ps1_path} %temp%\T1036.003_masquerading.pdf.ps1 /Y
copy #{ps1_path} %temp%\T1036.003_masquerading.rtf.ps1 /Y
%temp%\T1036.003_masquerading.docx.exe
%temp%\T1036.003_masquerading.pdf.exe
%temp%\T1036.003_masquerading.ps1.exe
%temp%\T1036.003_masquerading.xls.vbs
%temp%\T1036.003_masquerading.xlsx.vbs
%temp%\T1036.003_masquerading.png.vbs
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File %temp%\T1036.003_masquerading.doc.ps1
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File %temp%\T1036.003_masquerading.pdf.ps1
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File %temp%\T1036.003_masquerading.rtf.ps1
copy %SystemRoot%\System32\wscript.exe %APPDATA%\svchost.exe /Y
cmd.exe /c %APPDATA%\svchost.exe /B
copy %windir%\System32\windowspowershell\v1.0\powershell.exe %APPDATA%\taskhostw.exe /Y
cmd.exe /K %APPDATA%\taskhostw.exe
copy #{exe_path} %temp%\T1036.003_masquerading.docx.exe /Y
copy #{exe_path} %temp%\T1036.003_masquerading.pdf.exe /Y
copy #{exe_path} %temp%\T1036.003_masquerading.ps1.exe /Y
copy #{vbs_path} %temp%\T1036.003_masquerading.xls.vbs /Y
copy #{vbs_path} %temp%\T1036.003_masquerading.xlsx.vbs /Y
copy #{vbs_path} %temp%\T1036.003_masquerading.png.vbs /Y
copy PathToAtomicsFolder\T1036.003\src\T1036.003_masquerading.ps1 %temp%\T1036.003_masquerading.doc.ps1 /Y
copy PathToAtomicsFolder\T1036.003\src\T1036.003_masquerading.ps1 %temp%\T1036.003_masquerading.pdf.ps1 /Y
copy PathToAtomicsFolder\T1036.003\src\T1036.003_masquerading.ps1 %temp%\T1036.003_masquerading.rtf.ps1 /Y
%temp%\T1036.003_masquerading.docx.exe
%temp%\T1036.003_masquerading.pdf.exe
%temp%\T1036.003_masquerading.ps1.exe
%temp%\T1036.003_masquerading.xls.vbs
%temp%\T1036.003_masquerading.xlsx.vbs
%temp%\T1036.003_masquerading.png.vbs
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File %temp%\T1036.003_masquerading.doc.ps1
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File %temp%\T1036.003_masquerading.pdf.ps1
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File %temp%\T1036.003_masquerading.rtf.ps1
copy %SystemRoot%\System32\cscript.exe %APPDATA%\notepad.exe /Y
cmd.exe /c %APPDATA%\notepad.exe /B
copy PathToAtomicsFolder\T1036.003\bin\T1036.003.exe #{outputfile}
$myT1036_003 = (Start-Process -PassThru -FilePath #{outputfile}).Id
Stop-Process -ID $myT1036_003
copy $env:ComSpec #{outputfile}
$myT1036_003 = (Start-Process -PassThru -FilePath #{outputfile}).Id
Stop-Process -ID $myT1036_003
copy C:\Windows\System32\cmd.exe C:\lsm.exe
C:\lsm.exe /c echo T1036.003 > C:\T1036.003.txt
copy #{inputfile} ($env:TEMP + "\svchost.exe")
$myT1036_003 = (Start-Process -PassThru -FilePath ($env:TEMP + "\svchost.exe")).Id
Stop-Process -ID $myT1036_003
copy C:\Windows\System32\calc.exe %temp%\T1036.003_masquerading.docx.exe /Y
copy C:\Windows\System32\calc.exe %temp%\T1036.003_masquerading.pdf.exe /Y
copy C:\Windows\System32\calc.exe %temp%\T1036.003_masquerading.ps1.exe /Y
copy #{vbs_path} %temp%\T1036.003_masquerading.xls.vbs /Y
copy #{vbs_path} %temp%\T1036.003_masquerading.xlsx.vbs /Y
copy #{vbs_path} %temp%\T1036.003_masquerading.png.vbs /Y
copy #{ps1_path} %temp%\T1036.003_masquerading.doc.ps1 /Y
copy #{ps1_path} %temp%\T1036.003_masquerading.pdf.ps1 /Y
copy #{ps1_path} %temp%\T1036.003_masquerading.rtf.ps1 /Y
%temp%\T1036.003_masquerading.docx.exe
%temp%\T1036.003_masquerading.pdf.exe
%temp%\T1036.003_masquerading.ps1.exe
%temp%\T1036.003_masquerading.xls.vbs
%temp%\T1036.003_masquerading.xlsx.vbs
%temp%\T1036.003_masquerading.png.vbs
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File %temp%\T1036.003_masquerading.doc.ps1
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File %temp%\T1036.003_masquerading.pdf.ps1
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -File %temp%\T1036.003_masquerading.rtf.ps1
copy %SystemRoot%\System32\cmd.exe %SystemRoot%\Temp\lsass.exe
%SystemRoot%\Temp\lsass.exe /B
```

## Commands Dataset

```
[{'command': 'copy %SystemRoot%\\System32\\cmd.exe '
             '%SystemRoot%\\Temp\\lsass.exe\n'
             '%SystemRoot%\\Temp\\lsass.exe /B\n',
  'name': None,
  'source': 'atomics/T1036.003/T1036.003.yaml'},
 {'command': 'cp /bin/sh /tmp/crond;\n/tmp/crond\n',
  'name': None,
  'source': 'atomics/T1036.003/T1036.003.yaml'},
 {'command': 'copy %SystemRoot%\\System32\\cscript.exe %APPDATA%\\notepad.exe '
             '/Y\n'
             'cmd.exe /c %APPDATA%\\notepad.exe /B\n',
  'name': None,
  'source': 'atomics/T1036.003/T1036.003.yaml'},
 {'command': 'copy %SystemRoot%\\System32\\wscript.exe %APPDATA%\\svchost.exe '
             '/Y\n'
             'cmd.exe /c %APPDATA%\\svchost.exe /B\n',
  'name': None,
  'source': 'atomics/T1036.003/T1036.003.yaml'},
 {'command': 'copy %windir%\\System32\\windowspowershell\\v1.0\\powershell.exe '
             '%APPDATA%\\taskhostw.exe /Y\n'
             'cmd.exe /K %APPDATA%\\taskhostw.exe\n',
  'name': None,
  'source': 'atomics/T1036.003/T1036.003.yaml'},
 {'command': 'copy #{inputfile} ($env:TEMP + "\\svchost.exe")\n'
             '$myT1036_003 = (Start-Process -PassThru -FilePath ($env:TEMP + '
             '"\\svchost.exe")).Id\n'
             'Stop-Process -ID $myT1036_003\n',
  'name': None,
  'source': 'atomics/T1036.003/T1036.003.yaml'},
 {'command': 'copy PathToAtomicsFolder\\T1036.003\\bin\\T1036.003.exe '
             '#{outputfile}\n'
             '$myT1036_003 = (Start-Process -PassThru -FilePath '
             '#{outputfile}).Id\n'
             'Stop-Process -ID $myT1036_003\n',
  'name': None,
  'source': 'atomics/T1036.003/T1036.003.yaml'},
 {'command': 'copy #{inputfile} ($env:TEMP + "\\svchost.exe")\n'
             '$myT1036_003 = (Start-Process -PassThru -FilePath ($env:TEMP + '
             '"\\svchost.exe")).Id\n'
             'Stop-Process -ID $myT1036_003\n',
  'name': None,
  'source': 'atomics/T1036.003/T1036.003.yaml'},
 {'command': 'copy $env:ComSpec #{outputfile}\n'
             '$myT1036_003 = (Start-Process -PassThru -FilePath '
             '#{outputfile}).Id\n'
             'Stop-Process -ID $myT1036_003\n',
  'name': None,
  'source': 'atomics/T1036.003/T1036.003.yaml'},
 {'command': 'copy C:\\Windows\\System32\\cmd.exe C:\\lsm.exe\n'
             'C:\\lsm.exe /c echo T1036.003 > C:\\T1036.003.txt\n',
  'name': None,
  'source': 'atomics/T1036.003/T1036.003.yaml'},
 {'command': 'copy C:\\Windows\\System32\\calc.exe '
             '%temp%\\T1036.003_masquerading.docx.exe /Y\n'
             'copy C:\\Windows\\System32\\calc.exe '
             '%temp%\\T1036.003_masquerading.pdf.exe /Y\n'
             'copy C:\\Windows\\System32\\calc.exe '
             '%temp%\\T1036.003_masquerading.ps1.exe /Y\n'
             'copy #{vbs_path} %temp%\\T1036.003_masquerading.xls.vbs /Y\n'
             'copy #{vbs_path} %temp%\\T1036.003_masquerading.xlsx.vbs /Y\n'
             'copy #{vbs_path} %temp%\\T1036.003_masquerading.png.vbs /Y\n'
             'copy #{ps1_path} %temp%\\T1036.003_masquerading.doc.ps1 /Y\n'
             'copy #{ps1_path} %temp%\\T1036.003_masquerading.pdf.ps1 /Y\n'
             'copy #{ps1_path} %temp%\\T1036.003_masquerading.rtf.ps1 /Y\n'
             '%temp%\\T1036.003_masquerading.docx.exe\n'
             '%temp%\\T1036.003_masquerading.pdf.exe\n'
             '%temp%\\T1036.003_masquerading.ps1.exe\n'
             '%temp%\\T1036.003_masquerading.xls.vbs\n'
             '%temp%\\T1036.003_masquerading.xlsx.vbs\n'
             '%temp%\\T1036.003_masquerading.png.vbs\n'
             'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
             '-File %temp%\\T1036.003_masquerading.doc.ps1\n'
             'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
             '-File %temp%\\T1036.003_masquerading.pdf.ps1\n'
             'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
             '-File %temp%\\T1036.003_masquerading.rtf.ps1\n',
  'name': None,
  'source': 'atomics/T1036.003/T1036.003.yaml'},
 {'command': 'copy #{exe_path} %temp%\\T1036.003_masquerading.docx.exe /Y\n'
             'copy #{exe_path} %temp%\\T1036.003_masquerading.pdf.exe /Y\n'
             'copy #{exe_path} %temp%\\T1036.003_masquerading.ps1.exe /Y\n'
             'copy '
             'PathToAtomicsFolder\\T1036.003\\src\\T1036.003_masquerading.vbs '
             '%temp%\\T1036.003_masquerading.xls.vbs /Y\n'
             'copy '
             'PathToAtomicsFolder\\T1036.003\\src\\T1036.003_masquerading.vbs '
             '%temp%\\T1036.003_masquerading.xlsx.vbs /Y\n'
             'copy '
             'PathToAtomicsFolder\\T1036.003\\src\\T1036.003_masquerading.vbs '
             '%temp%\\T1036.003_masquerading.png.vbs /Y\n'
             'copy #{ps1_path} %temp%\\T1036.003_masquerading.doc.ps1 /Y\n'
             'copy #{ps1_path} %temp%\\T1036.003_masquerading.pdf.ps1 /Y\n'
             'copy #{ps1_path} %temp%\\T1036.003_masquerading.rtf.ps1 /Y\n'
             '%temp%\\T1036.003_masquerading.docx.exe\n'
             '%temp%\\T1036.003_masquerading.pdf.exe\n'
             '%temp%\\T1036.003_masquerading.ps1.exe\n'
             '%temp%\\T1036.003_masquerading.xls.vbs\n'
             '%temp%\\T1036.003_masquerading.xlsx.vbs\n'
             '%temp%\\T1036.003_masquerading.png.vbs\n'
             'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
             '-File %temp%\\T1036.003_masquerading.doc.ps1\n'
             'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
             '-File %temp%\\T1036.003_masquerading.pdf.ps1\n'
             'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
             '-File %temp%\\T1036.003_masquerading.rtf.ps1\n',
  'name': None,
  'source': 'atomics/T1036.003/T1036.003.yaml'},
 {'command': 'copy #{exe_path} %temp%\\T1036.003_masquerading.docx.exe /Y\n'
             'copy #{exe_path} %temp%\\T1036.003_masquerading.pdf.exe /Y\n'
             'copy #{exe_path} %temp%\\T1036.003_masquerading.ps1.exe /Y\n'
             'copy #{vbs_path} %temp%\\T1036.003_masquerading.xls.vbs /Y\n'
             'copy #{vbs_path} %temp%\\T1036.003_masquerading.xlsx.vbs /Y\n'
             'copy #{vbs_path} %temp%\\T1036.003_masquerading.png.vbs /Y\n'
             'copy '
             'PathToAtomicsFolder\\T1036.003\\src\\T1036.003_masquerading.ps1 '
             '%temp%\\T1036.003_masquerading.doc.ps1 /Y\n'
             'copy '
             'PathToAtomicsFolder\\T1036.003\\src\\T1036.003_masquerading.ps1 '
             '%temp%\\T1036.003_masquerading.pdf.ps1 /Y\n'
             'copy '
             'PathToAtomicsFolder\\T1036.003\\src\\T1036.003_masquerading.ps1 '
             '%temp%\\T1036.003_masquerading.rtf.ps1 /Y\n'
             '%temp%\\T1036.003_masquerading.docx.exe\n'
             '%temp%\\T1036.003_masquerading.pdf.exe\n'
             '%temp%\\T1036.003_masquerading.ps1.exe\n'
             '%temp%\\T1036.003_masquerading.xls.vbs\n'
             '%temp%\\T1036.003_masquerading.xlsx.vbs\n'
             '%temp%\\T1036.003_masquerading.png.vbs\n'
             'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
             '-File %temp%\\T1036.003_masquerading.doc.ps1\n'
             'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
             '-File %temp%\\T1036.003_masquerading.pdf.ps1\n'
             'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
             '-File %temp%\\T1036.003_masquerading.rtf.ps1\n',
  'name': None,
  'source': 'atomics/T1036.003/T1036.003.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Masquerading: Rename System Utilities': {'atomic_tests': [{'auto_generated_guid': '5ba5a3d1-cf3c-4499-968a-a93155d1f717',
                                                                                     'description': 'Copies '
                                                                                                    'cmd.exe, '
                                                                                                    'renames '
                                                                                                    'it, '
                                                                                                    'and '
                                                                                                    'launches '
                                                                                                    'it '
                                                                                                    'to '
                                                                                                    'masquerade '
                                                                                                    'as '
                                                                                                    'an '
                                                                                                    'instance '
                                                                                                    'of '
                                                                                                    'lsass.exe.\n'
                                                                                                    '\n'
                                                                                                    'Upon '
                                                                                                    'execution, '
                                                                                                    'cmd '
                                                                                                    'will '
                                                                                                    'be '
                                                                                                    'launched '
                                                                                                    'by '
                                                                                                    'powershell. '
                                                                                                    'If '
                                                                                                    'using '
                                                                                                    'Invoke-AtomicTest, '
                                                                                                    'The '
                                                                                                    'test '
                                                                                                    'will '
                                                                                                    'hang '
                                                                                                    'until '
                                                                                                    'the '
                                                                                                    '120 '
                                                                                                    'second '
                                                                                                    'timeout '
                                                                                                    'cancels '
                                                                                                    'the '
                                                                                                    'session\n',
                                                                                     'executor': {'cleanup_command': 'del '
                                                                                                                     '/Q '
                                                                                                                     '/F '
                                                                                                                     '%SystemRoot%\\Temp\\lsass.exe '
                                                                                                                     '>nul '
                                                                                                                     '2>&1\n',
                                                                                                  'command': 'copy '
                                                                                                             '%SystemRoot%\\System32\\cmd.exe '
                                                                                                             '%SystemRoot%\\Temp\\lsass.exe\n'
                                                                                                             '%SystemRoot%\\Temp\\lsass.exe '
                                                                                                             '/B\n',
                                                                                                  'name': 'command_prompt'},
                                                                                     'name': 'Masquerading '
                                                                                             'as '
                                                                                             'Windows '
                                                                                             'LSASS '
                                                                                             'process',
                                                                                     'supported_platforms': ['windows']},
                                                                                    {'auto_generated_guid': 'a315bfff-7a98-403b-b442-2ea1b255e556',
                                                                                     'description': 'Copies '
                                                                                                    'sh '
                                                                                                    'process, '
                                                                                                    'renames '
                                                                                                    'it '
                                                                                                    'as '
                                                                                                    'crond, '
                                                                                                    'and '
                                                                                                    'executes '
                                                                                                    'it '
                                                                                                    'to '
                                                                                                    'masquerade '
                                                                                                    'as '
                                                                                                    'the '
                                                                                                    'cron '
                                                                                                    'daemon.\n'
                                                                                                    '\n'
                                                                                                    'Upon '
                                                                                                    'successful '
                                                                                                    'execution, '
                                                                                                    'sh '
                                                                                                    'is '
                                                                                                    'renamed '
                                                                                                    'to '
                                                                                                    '`crond` '
                                                                                                    'and '
                                                                                                    'executed.\n',
                                                                                     'executor': {'cleanup_command': 'rm '
                                                                                                                     '/tmp/crond\n',
                                                                                                  'command': 'cp '
                                                                                                             '/bin/sh '
                                                                                                             '/tmp/crond;\n'
                                                                                                             '/tmp/crond\n',
                                                                                                  'name': 'sh'},
                                                                                     'name': 'Masquerading '
                                                                                             'as '
                                                                                             'Linux '
                                                                                             'crond '
                                                                                             'process.',
                                                                                     'supported_platforms': ['linux']},
                                                                                    {'auto_generated_guid': '3a2a578b-0a01-46e4-92e3-62e2859b42f0',
                                                                                     'description': 'Copies '
                                                                                                    'cscript.exe, '
                                                                                                    'renames '
                                                                                                    'it, '
                                                                                                    'and '
                                                                                                    'launches '
                                                                                                    'it '
                                                                                                    'to '
                                                                                                    'masquerade '
                                                                                                    'as '
                                                                                                    'an '
                                                                                                    'instance '
                                                                                                    'of '
                                                                                                    'notepad.exe.\n'
                                                                                                    '\n'
                                                                                                    'Upon '
                                                                                                    'successful '
                                                                                                    'execution, '
                                                                                                    'cscript.exe '
                                                                                                    'is '
                                                                                                    'renamed '
                                                                                                    'as '
                                                                                                    'notepad.exe '
                                                                                                    'and '
                                                                                                    'executed '
                                                                                                    'from '
                                                                                                    'non-standard '
                                                                                                    'path.\n',
                                                                                     'executor': {'cleanup_command': 'del '
                                                                                                                     '/Q '
                                                                                                                     '/F '
                                                                                                                     '%APPDATA%\\notepad.exe '
                                                                                                                     '>nul '
                                                                                                                     '2>&1\n',
                                                                                                  'command': 'copy '
                                                                                                             '%SystemRoot%\\System32\\cscript.exe '
                                                                                                             '%APPDATA%\\notepad.exe '
                                                                                                             '/Y\n'
                                                                                                             'cmd.exe '
                                                                                                             '/c '
                                                                                                             '%APPDATA%\\notepad.exe '
                                                                                                             '/B\n',
                                                                                                  'name': 'command_prompt'},
                                                                                     'name': 'Masquerading '
                                                                                             '- '
                                                                                             'cscript.exe '
                                                                                             'running '
                                                                                             'as '
                                                                                             'notepad.exe',
                                                                                     'supported_platforms': ['windows']},
                                                                                    {'auto_generated_guid': '24136435-c91a-4ede-9da1-8b284a1c1a23',
                                                                                     'description': 'Copies '
                                                                                                    'wscript.exe, '
                                                                                                    'renames '
                                                                                                    'it, '
                                                                                                    'and '
                                                                                                    'launches '
                                                                                                    'it '
                                                                                                    'to '
                                                                                                    'masquerade '
                                                                                                    'as '
                                                                                                    'an '
                                                                                                    'instance '
                                                                                                    'of '
                                                                                                    'svchost.exe.\n'
                                                                                                    '\n'
                                                                                                    'Upon '
                                                                                                    'execution, '
                                                                                                    'no '
                                                                                                    'windows '
                                                                                                    'will '
                                                                                                    'remain '
                                                                                                    'open '
                                                                                                    'but '
                                                                                                    'wscript '
                                                                                                    'will '
                                                                                                    'have '
                                                                                                    'been '
                                                                                                    'renamed '
                                                                                                    'to '
                                                                                                    'svchost '
                                                                                                    'and '
                                                                                                    'ran '
                                                                                                    'out '
                                                                                                    'of '
                                                                                                    'the '
                                                                                                    'temp '
                                                                                                    'folder\n',
                                                                                     'executor': {'cleanup_command': 'del '
                                                                                                                     '/Q '
                                                                                                                     '/F '
                                                                                                                     '%APPDATA%\\svchost.exe '
                                                                                                                     '>nul '
                                                                                                                     '2>&1\n',
                                                                                                  'command': 'copy '
                                                                                                             '%SystemRoot%\\System32\\wscript.exe '
                                                                                                             '%APPDATA%\\svchost.exe '
                                                                                                             '/Y\n'
                                                                                                             'cmd.exe '
                                                                                                             '/c '
                                                                                                             '%APPDATA%\\svchost.exe '
                                                                                                             '/B\n',
                                                                                                  'name': 'command_prompt'},
                                                                                     'name': 'Masquerading '
                                                                                             '- '
                                                                                             'wscript.exe '
                                                                                             'running '
                                                                                             'as '
                                                                                             'svchost.exe',
                                                                                     'supported_platforms': ['windows']},
                                                                                    {'auto_generated_guid': 'ac9d0fc3-8aa8-4ab5-b11f-682cd63b40aa',
                                                                                     'description': 'Copies '
                                                                                                    'powershell.exe, '
                                                                                                    'renames '
                                                                                                    'it, '
                                                                                                    'and '
                                                                                                    'launches '
                                                                                                    'it '
                                                                                                    'to '
                                                                                                    'masquerade '
                                                                                                    'as '
                                                                                                    'an '
                                                                                                    'instance '
                                                                                                    'of '
                                                                                                    'taskhostw.exe.\n'
                                                                                                    '\n'
                                                                                                    'Upon '
                                                                                                    'successful '
                                                                                                    'execution, '
                                                                                                    'powershell.exe '
                                                                                                    'is '
                                                                                                    'renamed '
                                                                                                    'as '
                                                                                                    'taskhostw.exe '
                                                                                                    'and '
                                                                                                    'executed '
                                                                                                    'from '
                                                                                                    'non-standard '
                                                                                                    'path.\n',
                                                                                     'executor': {'cleanup_command': 'del '
                                                                                                                     '/Q '
                                                                                                                     '/F '
                                                                                                                     '%APPDATA%\\taskhostw.exe '
                                                                                                                     '>nul '
                                                                                                                     '2>&1\n',
                                                                                                  'command': 'copy '
                                                                                                             '%windir%\\System32\\windowspowershell\\v1.0\\powershell.exe '
                                                                                                             '%APPDATA%\\taskhostw.exe '
                                                                                                             '/Y\n'
                                                                                                             'cmd.exe '
                                                                                                             '/K '
                                                                                                             '%APPDATA%\\taskhostw.exe\n',
                                                                                                  'name': 'command_prompt'},
                                                                                     'name': 'Masquerading '
                                                                                             '- '
                                                                                             'powershell.exe '
                                                                                             'running '
                                                                                             'as '
                                                                                             'taskhostw.exe',
                                                                                     'supported_platforms': ['windows']},
                                                                                    {'auto_generated_guid': 'bc15c13f-d121-4b1f-8c7d-28d95854d086',
                                                                                     'dependencies': [{'description': 'Exe '
                                                                                                                      'file '
                                                                                                                      'to '
                                                                                                                      'copy '
                                                                                                                      'must '
                                                                                                                      'exist '
                                                                                                                      'on '
                                                                                                                      'disk '
                                                                                                                      'at '
                                                                                                                      'specified '
                                                                                                                      'location '
                                                                                                                      '(#{inputfile})\n',
                                                                                                       'get_prereq_command': 'New-Item '
                                                                                                                             '-Type '
                                                                                                                             'Directory '
                                                                                                                             '(split-path '
                                                                                                                             '#{inputfile}) '
                                                                                                                             '-ErrorAction '
                                                                                                                             'ignore '
                                                                                                                             '| '
                                                                                                                             'Out-Null\n'
                                                                                                                             'Invoke-WebRequest '
                                                                                                                             '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1036.003/bin/T1036.003.exe" '
                                                                                                                             '-OutFile '
                                                                                                                             '"#{inputfile}"\n',
                                                                                                       'prereq_command': 'if '
                                                                                                                         '(Test-Path '
                                                                                                                         '#{inputfile}) '
                                                                                                                         '{exit '
                                                                                                                         '0} '
                                                                                                                         'else '
                                                                                                                         '{exit '
                                                                                                                         '1}\n'}],
                                                                                     'dependency_executor_name': 'powershell',
                                                                                     'description': 'Copies '
                                                                                                    'an '
                                                                                                    'exe, '
                                                                                                    'renames '
                                                                                                    'it '
                                                                                                    'as '
                                                                                                    'a '
                                                                                                    'windows '
                                                                                                    'exe, '
                                                                                                    'and '
                                                                                                    'launches '
                                                                                                    'it '
                                                                                                    'to '
                                                                                                    'masquerade '
                                                                                                    'as '
                                                                                                    'a '
                                                                                                    'real '
                                                                                                    'windows '
                                                                                                    'exe\n'
                                                                                                    '\n'
                                                                                                    'Upon '
                                                                                                    'successful '
                                                                                                    'execution, '
                                                                                                    'powershell '
                                                                                                    'will '
                                                                                                    'execute '
                                                                                                    'T1036.003.exe '
                                                                                                    'as '
                                                                                                    'svchost.exe '
                                                                                                    'from '
                                                                                                    'on '
                                                                                                    'a '
                                                                                                    'non-standard '
                                                                                                    'path.\n',
                                                                                     'executor': {'cleanup_command': 'Remove-Item '
                                                                                                                     '#{outputfile} '
                                                                                                                     '-Force '
                                                                                                                     '-ErrorAction '
                                                                                                                     'Ignore\n',
                                                                                                  'command': 'copy '
                                                                                                             '#{inputfile} '
                                                                                                             '#{outputfile}\n'
                                                                                                             '$myT1036_003 '
                                                                                                             '= '
                                                                                                             '(Start-Process '
                                                                                                             '-PassThru '
                                                                                                             '-FilePath '
                                                                                                             '#{outputfile}).Id\n'
                                                                                                             'Stop-Process '
                                                                                                             '-ID '
                                                                                                             '$myT1036_003\n',
                                                                                                  'name': 'powershell'},
                                                                                     'input_arguments': {'inputfile': {'default': 'PathToAtomicsFolder\\T1036.003\\bin\\T1036.003.exe',
                                                                                                                       'description': 'path '
                                                                                                                                      'of '
                                                                                                                                      'file '
                                                                                                                                      'to '
                                                                                                                                      'copy',
                                                                                                                       'type': 'path'},
                                                                                                         'outputfile': {'default': '($env:TEMP '
                                                                                                                                   '+ '
                                                                                                                                   '"\\svchost.exe")',
                                                                                                                        'description': 'path '
                                                                                                                                       'of '
                                                                                                                                       'file '
                                                                                                                                       'to '
                                                                                                                                       'execute',
                                                                                                                        'type': 'path'}},
                                                                                     'name': 'Masquerading '
                                                                                             '- '
                                                                                             'non-windows '
                                                                                             'exe '
                                                                                             'running '
                                                                                             'as '
                                                                                             'windows '
                                                                                             'exe',
                                                                                     'supported_platforms': ['windows']},
                                                                                    {'auto_generated_guid': 'c3d24a39-2bfe-4c6a-b064-90cd73896cb0',
                                                                                     'description': 'Copies '
                                                                                                    'a '
                                                                                                    'windows '
                                                                                                    'exe, '
                                                                                                    'renames '
                                                                                                    'it '
                                                                                                    'as '
                                                                                                    'another '
                                                                                                    'windows '
                                                                                                    'exe, '
                                                                                                    'and '
                                                                                                    'launches '
                                                                                                    'it '
                                                                                                    'to '
                                                                                                    'masquerade '
                                                                                                    'as '
                                                                                                    'second '
                                                                                                    'windows '
                                                                                                    'exe\n',
                                                                                     'executor': {'cleanup_command': 'Remove-Item '
                                                                                                                     '#{outputfile} '
                                                                                                                     '-Force '
                                                                                                                     '-ErrorAction '
                                                                                                                     'Ignore\n',
                                                                                                  'command': 'copy '
                                                                                                             '#{inputfile} '
                                                                                                             '#{outputfile}\n'
                                                                                                             '$myT1036_003 '
                                                                                                             '= '
                                                                                                             '(Start-Process '
                                                                                                             '-PassThru '
                                                                                                             '-FilePath '
                                                                                                             '#{outputfile}).Id\n'
                                                                                                             'Stop-Process '
                                                                                                             '-ID '
                                                                                                             '$myT1036_003\n',
                                                                                                  'name': 'powershell'},
                                                                                     'input_arguments': {'inputfile': {'default': '$env:ComSpec',
                                                                                                                       'description': 'path '
                                                                                                                                      'of '
                                                                                                                                      'file '
                                                                                                                                      'to '
                                                                                                                                      'copy',
                                                                                                                       'type': 'path'},
                                                                                                         'outputfile': {'default': '($env:TEMP '
                                                                                                                                   '+ '
                                                                                                                                   '"\\svchost.exe")',
                                                                                                                        'description': 'path '
                                                                                                                                       'of '
                                                                                                                                       'file '
                                                                                                                                       'to '
                                                                                                                                       'execute',
                                                                                                                        'type': 'path'}},
                                                                                     'name': 'Masquerading '
                                                                                             '- '
                                                                                             'windows '
                                                                                             'exe '
                                                                                             'running '
                                                                                             'as '
                                                                                             'different '
                                                                                             'windows '
                                                                                             'exe',
                                                                                     'supported_platforms': ['windows']},
                                                                                    {'auto_generated_guid': '83810c46-f45e-4485-9ab6-8ed0e9e6ed7f',
                                                                                     'description': 'Detect '
                                                                                                    'LSM '
                                                                                                    'running '
                                                                                                    'from '
                                                                                                    'an '
                                                                                                    'incorrect '
                                                                                                    'directory '
                                                                                                    'and '
                                                                                                    'an '
                                                                                                    'incorrect '
                                                                                                    'service '
                                                                                                    'account\n'
                                                                                                    'This '
                                                                                                    'works '
                                                                                                    'by '
                                                                                                    'copying '
                                                                                                    'cmd.exe '
                                                                                                    'to '
                                                                                                    'a '
                                                                                                    'file, '
                                                                                                    'naming '
                                                                                                    'it '
                                                                                                    'lsm.exe, '
                                                                                                    'then '
                                                                                                    'copying '
                                                                                                    'a '
                                                                                                    'file '
                                                                                                    'to '
                                                                                                    'the '
                                                                                                    'C:\\ '
                                                                                                    'folder.\n'
                                                                                                    '\n'
                                                                                                    'Upon '
                                                                                                    'successful '
                                                                                                    'execution, '
                                                                                                    'cmd.exe '
                                                                                                    'will '
                                                                                                    'be '
                                                                                                    'renamed '
                                                                                                    'as '
                                                                                                    'lsm.exe '
                                                                                                    'and '
                                                                                                    'executed '
                                                                                                    'from '
                                                                                                    'non-standard '
                                                                                                    'path.\n',
                                                                                     'executor': {'cleanup_command': 'del '
                                                                                                                     'C:\\T1036.003.txt '
                                                                                                                     '>nul '
                                                                                                                     '2>&1\n'
                                                                                                                     'del '
                                                                                                                     'C:\\lsm.exe '
                                                                                                                     '>nul '
                                                                                                                     '2>&1\n',
                                                                                                  'command': 'copy '
                                                                                                             'C:\\Windows\\System32\\cmd.exe '
                                                                                                             'C:\\lsm.exe\n'
                                                                                                             'C:\\lsm.exe '
                                                                                                             '/c '
                                                                                                             'echo '
                                                                                                             'T1036.003 '
                                                                                                             '> '
                                                                                                             'C:\\T1036.003.txt\n',
                                                                                                  'elevation_required': True,
                                                                                                  'name': 'command_prompt'},
                                                                                     'name': 'Malicious '
                                                                                             'process '
                                                                                             'Masquerading '
                                                                                             'as '
                                                                                             'LSM.exe',
                                                                                     'supported_platforms': ['windows']},
                                                                                    {'auto_generated_guid': 'c7fa0c3b-b57f-4cba-9118-863bf4e653fc',
                                                                                     'description': 'download '
                                                                                                    'and '
                                                                                                    'execute '
                                                                                                    'a '
                                                                                                    'file '
                                                                                                    'masquerading '
                                                                                                    'as '
                                                                                                    'images '
                                                                                                    'or '
                                                                                                    'Office '
                                                                                                    'files. '
                                                                                                    'Upon '
                                                                                                    'execution '
                                                                                                    '3 '
                                                                                                    'calc '
                                                                                                    'instances '
                                                                                                    'and '
                                                                                                    '3 '
                                                                                                    'vbs '
                                                                                                    'windows '
                                                                                                    'will '
                                                                                                    'be '
                                                                                                    'launched.\n'
                                                                                                    '\n'
                                                                                                    'e.g '
                                                                                                    'SOME_LEGIT_NAME.[doc,docx,xls,xlsx,pdf,rtf,png,jpg,etc.].[exe,vbs,js,ps1,etc] '
                                                                                                    '(Quartelyreport.docx.exe)\n',
                                                                                     'executor': {'cleanup_command': 'del '
                                                                                                                     '/f '
                                                                                                                     '%temp%\\T1036.003_masquerading.docx.exe '
                                                                                                                     '> '
                                                                                                                     'nul '
                                                                                                                     '2>&1\n'
                                                                                                                     'del '
                                                                                                                     '/f '
                                                                                                                     '%temp%\\T1036.003_masquerading.pdf.exe '
                                                                                                                     '> '
                                                                                                                     'nul '
                                                                                                                     '2>&1\n'
                                                                                                                     'del '
                                                                                                                     '/f '
                                                                                                                     '%temp%\\T1036.003_masquerading.ps1.exe '
                                                                                                                     '> '
                                                                                                                     'nul '
                                                                                                                     '2>&1\n'
                                                                                                                     'del '
                                                                                                                     '/f '
                                                                                                                     '%temp%\\T1036.003_masquerading.xls.vbs '
                                                                                                                     '> '
                                                                                                                     'nul '
                                                                                                                     '2>&1\n'
                                                                                                                     'del '
                                                                                                                     '/f '
                                                                                                                     '%temp%\\T1036.003_masquerading.xlsx.vbs '
                                                                                                                     '> '
                                                                                                                     'nul '
                                                                                                                     '2>&1\n'
                                                                                                                     'del '
                                                                                                                     '/f '
                                                                                                                     '%temp%\\T1036.003_masquerading.png.vbs '
                                                                                                                     '> '
                                                                                                                     'nul '
                                                                                                                     '2>&1\n'
                                                                                                                     'del '
                                                                                                                     '/f '
                                                                                                                     '%temp%\\T1036.003_masquerading.doc.ps1 '
                                                                                                                     '> '
                                                                                                                     'nul '
                                                                                                                     '2>&1\n'
                                                                                                                     'del '
                                                                                                                     '/f '
                                                                                                                     '%temp%\\T1036.003_masquerading.pdf.ps1 '
                                                                                                                     '> '
                                                                                                                     'nul '
                                                                                                                     '2>&1\n'
                                                                                                                     'del '
                                                                                                                     '/f '
                                                                                                                     '%temp%\\T1036.003_masquerading.rtf.ps1 '
                                                                                                                     '> '
                                                                                                                     'nul '
                                                                                                                     '2>&1\n',
                                                                                                  'command': 'copy '
                                                                                                             '#{exe_path} '
                                                                                                             '%temp%\\T1036.003_masquerading.docx.exe '
                                                                                                             '/Y\n'
                                                                                                             'copy '
                                                                                                             '#{exe_path} '
                                                                                                             '%temp%\\T1036.003_masquerading.pdf.exe '
                                                                                                             '/Y\n'
                                                                                                             'copy '
                                                                                                             '#{exe_path} '
                                                                                                             '%temp%\\T1036.003_masquerading.ps1.exe '
                                                                                                             '/Y\n'
                                                                                                             'copy '
                                                                                                             '#{vbs_path} '
                                                                                                             '%temp%\\T1036.003_masquerading.xls.vbs '
                                                                                                             '/Y\n'
                                                                                                             'copy '
                                                                                                             '#{vbs_path} '
                                                                                                             '%temp%\\T1036.003_masquerading.xlsx.vbs '
                                                                                                             '/Y\n'
                                                                                                             'copy '
                                                                                                             '#{vbs_path} '
                                                                                                             '%temp%\\T1036.003_masquerading.png.vbs '
                                                                                                             '/Y\n'
                                                                                                             'copy '
                                                                                                             '#{ps1_path} '
                                                                                                             '%temp%\\T1036.003_masquerading.doc.ps1 '
                                                                                                             '/Y\n'
                                                                                                             'copy '
                                                                                                             '#{ps1_path} '
                                                                                                             '%temp%\\T1036.003_masquerading.pdf.ps1 '
                                                                                                             '/Y\n'
                                                                                                             'copy '
                                                                                                             '#{ps1_path} '
                                                                                                             '%temp%\\T1036.003_masquerading.rtf.ps1 '
                                                                                                             '/Y\n'
                                                                                                             '%temp%\\T1036.003_masquerading.docx.exe\n'
                                                                                                             '%temp%\\T1036.003_masquerading.pdf.exe\n'
                                                                                                             '%temp%\\T1036.003_masquerading.ps1.exe\n'
                                                                                                             '%temp%\\T1036.003_masquerading.xls.vbs\n'
                                                                                                             '%temp%\\T1036.003_masquerading.xlsx.vbs\n'
                                                                                                             '%temp%\\T1036.003_masquerading.png.vbs\n'
                                                                                                             'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
                                                                                                             '-File '
                                                                                                             '%temp%\\T1036.003_masquerading.doc.ps1\n'
                                                                                                             'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
                                                                                                             '-File '
                                                                                                             '%temp%\\T1036.003_masquerading.pdf.ps1\n'
                                                                                                             'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
                                                                                                             '-File '
                                                                                                             '%temp%\\T1036.003_masquerading.rtf.ps1\n',
                                                                                                  'name': 'command_prompt'},
                                                                                     'input_arguments': {'exe_path': {'default': 'C:\\Windows\\System32\\calc.exe',
                                                                                                                      'description': 'path '
                                                                                                                                     'to '
                                                                                                                                     'exe '
                                                                                                                                     'to '
                                                                                                                                     'use '
                                                                                                                                     'when '
                                                                                                                                     'creating '
                                                                                                                                     'masquerading '
                                                                                                                                     'files',
                                                                                                                      'type': 'path'},
                                                                                                         'ps1_path': {'default': 'PathToAtomicsFolder\\T1036.003\\src\\T1036.003_masquerading.ps1',
                                                                                                                      'description': 'path '
                                                                                                                                     'of '
                                                                                                                                     'powershell '
                                                                                                                                     'script '
                                                                                                                                     'to '
                                                                                                                                     'use '
                                                                                                                                     'when '
                                                                                                                                     'creating '
                                                                                                                                     'masquerading '
                                                                                                                                     'files',
                                                                                                                      'type': 'path'},
                                                                                                         'vbs_path': {'default': 'PathToAtomicsFolder\\T1036.003\\src\\T1036.003_masquerading.vbs',
                                                                                                                      'description': 'path '
                                                                                                                                     'of '
                                                                                                                                     'vbs '
                                                                                                                                     'to '
                                                                                                                                     'use '
                                                                                                                                     'when '
                                                                                                                                     'creating '
                                                                                                                                     'masquerading '
                                                                                                                                     'files',
                                                                                                                      'type': 'path'}},
                                                                                     'name': 'File '
                                                                                             'Extension '
                                                                                             'Masquerading',
                                                                                     'supported_platforms': ['windows']}],
                                                                   'attack_technique': 'T1036.003',
                                                                   'display_name': 'Masquerading: '
                                                                                   'Rename '
                                                                                   'System '
                                                                                   'Utilities'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)


# Actors


* [PLATINUM](../actors/PLATINUM.md)

* [Soft Cell](../actors/Soft-Cell.md)
    
* [APT32](../actors/APT32.md)
    
* [menuPass](../actors/menuPass.md)
    
