
# Regsvcs/Regasm

## Description

### MITRE Description

> Adversaries may abuse Regsvcs and Regasm to proxy execution of code through a trusted Windows utility. Regsvcs and Regasm are Windows command-line utilities that are used to register .NET [Component Object Model](https://attack.mitre.org/techniques/T1559/001) (COM) assemblies. Both are digitally signed by Microsoft. (Citation: MSDN Regsvcs) (Citation: MSDN Regasm)

Both utilities may be used to bypass application control through use of attributes within the binary to specify code that should be run before registration or unregistration: <code>[ComRegisterFunction]</code> or <code>[ComUnregisterFunction]</code> respectively. The code with the registration and unregistration attributes will be executed even if the process is run under insufficient privileges and fails to execute. (Citation: LOLBAS Regsvcs)(Citation: LOLBAS Regasm)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Digital Certificate Validation', 'Application control']
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1218/009

## Potential Commands

```
$key = 'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='
$Content = [System.Convert]::FromBase64String($key)
Set-Content $env:Temp\key.snk -Value $Content -Encoding Byte
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /out:"#{output_file}" /target:library /keyfile:$env:Temp\key.snk PathToAtomicsFolder\T1218.009\src\T1218.009.cs
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe #{output_file}
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /out:"#{output_file}" /target:library PathToAtomicsFolder\T1218.009\src\T1218.009.cs
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U #{output_file}
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /out:"%tmp%\T1218.009.dll" /target:library #{source_file}
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U %tmp%\T1218.009.dll
$key = 'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='
$Content = [System.Convert]::FromBase64String($key)
Set-Content $env:Temp\key.snk -Value $Content -Encoding Byte
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /r:System.EnterpriseServices.dll /out:"$Env:TEMP\T1218.009.dll" /target:library /keyfile:$env:Temp\key.snk #{source_file}
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe $Env:TEMP\T1218.009.dll
```

## Commands Dataset

```
[{'command': 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe '
             '/r:System.EnterpriseServices.dll /out:"%tmp%\\T1218.009.dll" '
             '/target:library #{source_file}\n'
             'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regasm.exe /U '
             '%tmp%\\T1218.009.dll\n',
  'name': None,
  'source': 'atomics/T1218.009/T1218.009.yaml'},
 {'command': 'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe '
             '/r:System.EnterpriseServices.dll /out:"#{output_file}" '
             '/target:library '
             'PathToAtomicsFolder\\T1218.009\\src\\T1218.009.cs\n'
             'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regasm.exe /U '
             '#{output_file}\n',
  'name': None,
  'source': 'atomics/T1218.009/T1218.009.yaml'},
 {'command': '$key = '
             "'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='\n"
             '$Content = [System.Convert]::FromBase64String($key)\n'
             'Set-Content $env:Temp\\key.snk -Value $Content -Encoding Byte\n'
             'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe '
             '/r:System.EnterpriseServices.dll /out:"$Env:TEMP\\T1218.009.dll" '
             '/target:library /keyfile:$env:Temp\\key.snk #{source_file}\n'
             'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regsvcs.exe '
             '$Env:TEMP\\T1218.009.dll\n',
  'name': None,
  'source': 'atomics/T1218.009/T1218.009.yaml'},
 {'command': '$key = '
             "'BwIAAAAkAABSU0EyAAQAAAEAAQBhXtvkSeH85E31z64cAX+X2PWGc6DHP9VaoD13CljtYau9SesUzKVLJdHphY5ppg5clHIGaL7nZbp6qukLH0lLEq/vW979GWzVAgSZaGVCFpuk6p1y69cSr3STlzljJrY76JIjeS4+RhbdWHp99y8QhwRllOC0qu/WxZaffHS2te/PKzIiTuFfcP46qxQoLR8s3QZhAJBnn9TGJkbix8MTgEt7hD1DC2hXv7dKaC531ZWqGXB54OnuvFbD5P2t+vyvZuHNmAy3pX0BDXqwEfoZZ+hiIk1YUDSNOE79zwnpVP1+BN0PK5QCPCS+6zujfRlQpJ+nfHLLicweJ9uT7OG3g/P+JpXGN0/+Hitolufo7Ucjh+WvZAU//dzrGny5stQtTmLxdhZbOsNDJpsqnzwEUfL5+o8OhujBHDm/ZQ0361mVsSVWrmgDPKHGGRx+7FbdgpBEq3m15/4zzg343V9NBwt1+qZU+TSVPU0wRvkWiZRerjmDdehJIboWsx4V8aiWx8FPPngEmNz89tBAQ8zbIrJFfmtYnj1fFmkNu3lglOefcacyYEHPX/tqcBuBIg/cpcDHps/6SGCCciX3tufnEeDMAQjmLku8X4zHcgJx6FpVK7qeEuvyV0OGKvNor9b/WKQHIHjkzG+z6nWHMoMYV5VMTZ0jLM5aZQ6ypwmFZaNmtL6KDzKv8L1YN2TkKjXEoWulXNliBpelsSJyuICplrCTPGGSxPGihT3rpZ9tbLZUefrFnLNiHfVjNi53Yg4='\n"
             '$Content = [System.Convert]::FromBase64String($key)\n'
             'Set-Content $env:Temp\\key.snk -Value $Content -Encoding Byte\n'
             'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe '
             '/r:System.EnterpriseServices.dll /out:"#{output_file}" '
             '/target:library /keyfile:$env:Temp\\key.snk '
             'PathToAtomicsFolder\\T1218.009\\src\\T1218.009.cs\n'
             'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\regsvcs.exe '
             '#{output_file}\n',
  'name': None,
  'source': 'atomics/T1218.009/T1218.009.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Signed Binary Proxy Execution: Regsvcs/Regasm': {'atomic_tests': [{'auto_generated_guid': '71bfbfac-60b1-4fc0-ac8b-2cedbbdcb112',
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
                                                                                                                                     '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.009/src/T1218.009.cs" '
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
                                                                                                          'name': 'command_prompt'},
                                                                                             'input_arguments': {'output_file': {'default': '%tmp%\\T1218.009.dll',
                                                                                                                                 'description': 'Location '
                                                                                                                                                'of '
                                                                                                                                                'the '
                                                                                                                                                'payload',
                                                                                                                                 'type': 'Path'},
                                                                                                                 'source_file': {'default': 'PathToAtomicsFolder\\T1218.009\\src\\T1218.009.cs',
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
                                                                                                                                     '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1218.009/src/T1218.009.cs" '
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
                                                                                                                             '$parentpath\\T1218.009.tlb '
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
                                                                                             'input_arguments': {'output_file': {'default': '$Env:TEMP\\T1218.009.dll',
                                                                                                                                 'description': 'Location '
                                                                                                                                                'of '
                                                                                                                                                'the '
                                                                                                                                                'payload',
                                                                                                                                 'type': 'Path'},
                                                                                                                 'source_file': {'default': 'PathToAtomicsFolder\\T1218.009\\src\\T1218.009.cs',
                                                                                                                                 'description': 'Location '
                                                                                                                                                'of '
                                                                                                                                                'the '
                                                                                                                                                'CSharp '
                                                                                                                                                'source_file',
                                                                                                                                 'type': 'Path'}},
                                                                                             'name': 'Regsvcs '
                                                                                                     'Uninstall '
                                                                                                     'Method '
                                                                                                     'Call '
                                                                                                     'Test',
                                                                                             'supported_platforms': ['windows']}],
                                                                           'attack_technique': 'T1218.009',
                                                                           'display_name': 'Signed '
                                                                                           'Binary '
                                                                                           'Proxy '
                                                                                           'Execution: '
                                                                                           'Regsvcs/Regasm'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Execution Prevention](../mitigations/Execution-Prevention.md)

* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    

# Actors

None
