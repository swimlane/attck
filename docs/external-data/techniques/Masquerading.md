
# Masquerading

## Description

### MITRE Description

> Masquerading occurs when the name or location of an executable, legitimate or malicious, is manipulated or abused for the sake of evading defenses and observation. Several different variations of this technique have been observed.

One variant is for an executable to be placed in a commonly trusted directory or given the name of a legitimate, trusted program. Alternatively, the filename given may be a close approximation of legitimate programs or something innocuous. An example of this is when a common system utility or program is moved and renamed to avoid detection based on its usage.(Citation: FireEye APT10 Sept 2018) This is done to bypass tools that trust executables by relying on file name or path, as well as to deceive defenders and system administrators into thinking a file is benign by associating the name with something that is thought to be legitimate.

A third variant uses the right-to-left override (RTLO or RLO) character (U+202E) as a means of tricking a user into executing what they think is a benign file type but is actually executable code. RTLO is a non-printing character that causes the text that follows it to be displayed in reverse.(Citation: Infosecinstitute RTLO Technique) For example, a Windows screensaver file named <code>March 25 \u202Excod.scr</code> will display as <code>March 25 rcs.docx</code>. A JavaScript file named <code>photo_high_re\u202Egnp.js</code> will be displayed as <code>photo_high_resj.png</code>. A common use of this technique is with spearphishing attachments since it can trick both end users and defenders if they are not aware of how their tools display and render the RTLO character. Use of the RTLO character has been seen in many targeted intrusion attempts and criminal activity.(Citation: Trend Micro PLEAD RTLO)(Citation: Kaspersky RTLO Cyber Crime) RTLO can be used in the Windows Registry as well, where regedit.exe displays the reversed characters but the command line tool reg.exe does not by default. 

Adversaries may modify a binary's metadata, including such fields as icons, version, name of the product, description, and copyright, to better blend in with the environment and increase chances of deceiving a security analyst or product.(Citation: Threatexpress MetaTwin 2017)

### Windows
In another variation of this technique, an adversary may use a renamed copy of a legitimate utility, such as rundll32.exe. (Citation: Endgame Masquerade Ball) An alternative case occurs when a legitimate utility is moved to a different directory and also renamed to avoid detections based on system utilities executing from non-standard paths. (Citation: F-Secure CozyDuke)

An example of abuse of trusted locations in Windows would be the <code>C:\Windows\System32</code> directory. Examples of trusted binary names that can be given to malicious binares include "explorer.exe" and "svchost.exe".

### Linux
Another variation of this technique includes malicious binaries changing the name of their running process to that of a trusted or benign process, after they have been launched as opposed to before. (Citation: Remaiten)

An example of abuse of trusted locations in Linux  would be the <code>/bin</code> directory. Examples of trusted binary names that can be given to malicious binaries include "rsyncd" and "dbus-inotifier". (Citation: Fysbis Palo Alto Analysis)  (Citation: Fysbis Dr Web Analysis)

## Additional Attributes

* Bypass: ['Whitelisting by file name or path']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1036

## Potential Commands

```
copy %SystemRoot%\System32\cmd.exe %SystemRoot%\Temp\lsass.exe
%SystemRoot%\Temp\lsass.exe /B

cp /bin/sh /tmp/crond
/tmp/crond

copy %SystemRoot%\System32\cscript.exe %APPDATA%\notepad.exe /Y
cmd.exe /c %APPDATA%\notepad.exe /B

copy %SystemRoot%\System32\wscript.exe %APPDATA%\svchost.exe /Y
cmd.exe /c %APPDATA%\svchost.exe /B

copy %windir%\System32\windowspowershell\v1.0\powershell.exe %APPDATA%\taskhostw.exe /Y
cmd.exe /K %APPDATA%\taskhostw.exe

copy PathToAtomicsFolder\T1036\bin\t1036.exe #{outputfile}
$myT1036 = (Start-Process -PassThru -FilePath #{outputfile}).Id
Stop-Process -ID $myT1036

copy #{inputfile} ($env:TEMP + "\svchost.exe")
$myT1036 = (Start-Process -PassThru -FilePath ($env:TEMP + "\svchost.exe")).Id
Stop-Process -ID $myT1036

copy $env:ComSpec #{outputfile}
$myT1036 = (Start-Process -PassThru -FilePath #{outputfile}).Id
Stop-Process -ID $myT1036

copy #{inputfile} ($env:TEMP + "\svchost.exe")
$myT1036 = (Start-Process -PassThru -FilePath ($env:TEMP + "\svchost.exe")).Id
Stop-Process -ID $myT1036

copy C:\Windows\System32\cmd.exe C:\lsm.exe
C:\lsm.exe /c echo T1036 > C:\T1036.txt

*.exe
\Recycle.bin
*.exe
\Users\All Users\
*.exe
\Users\Default\
*.exe
\Users\Public\
*.exe
\Perflogs\
*.exe
\config\systemprofile\
*.exe
\Windows\Fonts\
*.exe
\Windows\IME\
*.exe
\Windows\addins\
*.exe
\ProgramData\
csrsr.exe
csrss.exe
!=*\Windows\System32\
cssrss.exe
explorer.exe
!=*\Windows\System32\
iexplore.exe
isass.exe
lexplore.exe
lsm.exe
!=*\Windows\System32\
lssass.exe
mmc.exe
!=*\Windows\System32\
!=wininit.exe
lsass
run32dll.exe
rundII.exe
scvhost.exe
smss.exe
!=services.exe
svchost.exe
svchosts.exe
```

## Commands Dataset

```
[{'command': 'copy %SystemRoot%\\System32\\cmd.exe '
             '%SystemRoot%\\Temp\\lsass.exe\n'
             '%SystemRoot%\\Temp\\lsass.exe /B\n',
  'name': None,
  'source': 'atomics/T1036/T1036.yaml'},
 {'command': 'cp /bin/sh /tmp/crond\n/tmp/crond\n',
  'name': None,
  'source': 'atomics/T1036/T1036.yaml'},
 {'command': 'copy %SystemRoot%\\System32\\cscript.exe %APPDATA%\\notepad.exe '
             '/Y\n'
             'cmd.exe /c %APPDATA%\\notepad.exe /B\n',
  'name': None,
  'source': 'atomics/T1036/T1036.yaml'},
 {'command': 'copy %SystemRoot%\\System32\\wscript.exe %APPDATA%\\svchost.exe '
             '/Y\n'
             'cmd.exe /c %APPDATA%\\svchost.exe /B\n',
  'name': None,
  'source': 'atomics/T1036/T1036.yaml'},
 {'command': 'copy %windir%\\System32\\windowspowershell\\v1.0\\powershell.exe '
             '%APPDATA%\\taskhostw.exe /Y\n'
             'cmd.exe /K %APPDATA%\\taskhostw.exe\n',
  'name': None,
  'source': 'atomics/T1036/T1036.yaml'},
 {'command': 'copy PathToAtomicsFolder\\T1036\\bin\\t1036.exe #{outputfile}\n'
             '$myT1036 = (Start-Process -PassThru -FilePath #{outputfile}).Id\n'
             'Stop-Process -ID $myT1036\n',
  'name': None,
  'source': 'atomics/T1036/T1036.yaml'},
 {'command': 'copy #{inputfile} ($env:TEMP + "\\svchost.exe")\n'
             '$myT1036 = (Start-Process -PassThru -FilePath ($env:TEMP + '
             '"\\svchost.exe")).Id\n'
             'Stop-Process -ID $myT1036\n',
  'name': None,
  'source': 'atomics/T1036/T1036.yaml'},
 {'command': 'copy $env:ComSpec #{outputfile}\n'
             '$myT1036 = (Start-Process -PassThru -FilePath #{outputfile}).Id\n'
             'Stop-Process -ID $myT1036\n',
  'name': None,
  'source': 'atomics/T1036/T1036.yaml'},
 {'command': 'copy #{inputfile} ($env:TEMP + "\\svchost.exe")\n'
             '$myT1036 = (Start-Process -PassThru -FilePath ($env:TEMP + '
             '"\\svchost.exe")).Id\n'
             'Stop-Process -ID $myT1036\n',
  'name': None,
  'source': 'atomics/T1036/T1036.yaml'},
 {'command': 'copy C:\\Windows\\System32\\cmd.exe C:\\lsm.exe\n'
             'C:\\lsm.exe /c echo T1036 > C:\\T1036.txt\n',
  'name': None,
  'source': 'atomics/T1036/T1036.yaml'},
 {'command': '*.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': '\\Recycle.bin',
  'name': 'file_path',
  'source': 'Threat Hunting Tables'},
 {'command': '*.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': '\\Users\\All Users\\',
  'name': 'file_path',
  'source': 'Threat Hunting Tables'},
 {'command': '*.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': '\\Users\\Default\\',
  'name': 'file_path',
  'source': 'Threat Hunting Tables'},
 {'command': '*.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': '\\Users\\Public\\',
  'name': 'file_path',
  'source': 'Threat Hunting Tables'},
 {'command': '*.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': '\\Perflogs\\',
  'name': 'file_path',
  'source': 'Threat Hunting Tables'},
 {'command': '*.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': '\\config\\systemprofile\\',
  'name': 'file_path',
  'source': 'Threat Hunting Tables'},
 {'command': '*.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': '\\Windows\\Fonts\\',
  'name': 'file_path',
  'source': 'Threat Hunting Tables'},
 {'command': '*.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': '\\Windows\\IME\\',
  'name': 'file_path',
  'source': 'Threat Hunting Tables'},
 {'command': '*.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': '\\Windows\\addins\\',
  'name': 'file_path',
  'source': 'Threat Hunting Tables'},
 {'command': '*.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': '\\ProgramData\\',
  'name': 'file_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'csrsr.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'csrss.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': '!=*\\Windows\\System32\\',
  'name': 'file_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'cssrss.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'explorer.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': '!=*\\Windows\\System32\\',
  'name': 'file_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'iexplore.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'isass.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'lexplore.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'lsm.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': '!=*\\Windows\\System32\\',
  'name': 'file_path',
  'source': 'Threat Hunting Tables'},
 {'command': 'lssass.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'mmc.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': '!=*\\Windows\\System32\\',
  'name': 'file_path',
  'source': 'Threat Hunting Tables'},
 {'command': '!=wininit.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'lsass',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': 'run32dll.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'rundII.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'scvhost.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'smss.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': '!=services.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'},
 {'command': 'svchost.exe',
  'name': 'sub_process_1',
  'source': 'Threat Hunting Tables'},
 {'command': 'svchosts.exe',
  'name': 'parent_process',
  'source': 'Threat Hunting Tables'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Masquerading Extension',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_path contains ".doc."or '
           'process_path contains ".docx."or process_path contains ".xls."or '
           'process_path contains ".xlsx."or process_path contains ".pdf."or '
           'process_path contains ".rtf."or process_path contains ".jpg."or '
           'process_path contains ".png."or process_path contains ".jpeg."or '
           'process_path contains ".zip."or process_path contains ".rar."or '
           'process_path contains ".ppt."or process_path contains ".pptx.")'},
 {'name': 'Masquerading Location',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 11 and (process_path contains '
           '"SysWOW64"or process_path contains "System32"or process_path '
           'contains "AppData"or process_path contains "Temp")and (file_name '
           'contains ".exe"or file_name contains ".dll"or file_name contains '
           '".bat"or file_name contains ".com"or file_name contains ".ps1"or '
           'file_name contains ".py"or file_name contains ".js"or file_name '
           'contains ".vbs"or file_name contains ".hta")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Masquerading': {'atomic_tests': [{'description': 'Copies '
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
                                                                         'elevation_required': False,
                                                                         'name': 'command_prompt'},
                                                            'name': 'Masquerading '
                                                                    'as '
                                                                    'Windows '
                                                                    'LSASS '
                                                                    'process',
                                                            'supported_platforms': ['windows']},
                                                           {'description': 'Copies '
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
                                                            'executor': {'command': 'cp '
                                                                                    '/bin/sh '
                                                                                    '/tmp/crond\n'
                                                                                    '/tmp/crond\n',
                                                                         'elevation_required': False,
                                                                         'name': 'sh'},
                                                            'name': 'Masquerading '
                                                                    'as Linux '
                                                                    'crond '
                                                                    'process.',
                                                            'supported_platforms': ['linux']},
                                                           {'description': 'Copies '
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
                                                                         'elevation_required': False,
                                                                         'name': 'command_prompt'},
                                                            'name': 'Masquerading '
                                                                    '- '
                                                                    'cscript.exe '
                                                                    'running '
                                                                    'as '
                                                                    'notepad.exe',
                                                            'supported_platforms': ['windows']},
                                                           {'description': 'Copies '
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
                                                                         'elevation_required': False,
                                                                         'name': 'command_prompt'},
                                                            'name': 'Masquerading '
                                                                    '- '
                                                                    'wscript.exe '
                                                                    'running '
                                                                    'as '
                                                                    'svchost.exe',
                                                            'supported_platforms': ['windows']},
                                                           {'description': 'Copies '
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
                                                                         'elevation_required': False,
                                                                         'name': 'command_prompt'},
                                                            'name': 'Masquerading '
                                                                    '- '
                                                                    'powershell.exe '
                                                                    'running '
                                                                    'as '
                                                                    'taskhostw.exe',
                                                            'supported_platforms': ['windows']},
                                                           {'dependencies': [{'description': 'Exe '
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
                                                                                                    '"https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1036/bin/t1036.exe" '
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
                                                                           'T1036.exe '
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
                                                                                    '$myT1036 '
                                                                                    '= '
                                                                                    '(Start-Process '
                                                                                    '-PassThru '
                                                                                    '-FilePath '
                                                                                    '#{outputfile}).Id\n'
                                                                                    'Stop-Process '
                                                                                    '-ID '
                                                                                    '$myT1036\n',
                                                                         'elevation_required': False,
                                                                         'name': 'powershell'},
                                                            'input_arguments': {'inputfile': {'default': 'PathToAtomicsFolder\\T1036\\bin\\t1036.exe',
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
                                                           {'description': 'Copies '
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
                                                                                    '$myT1036 '
                                                                                    '= '
                                                                                    '(Start-Process '
                                                                                    '-PassThru '
                                                                                    '-FilePath '
                                                                                    '#{outputfile}).Id\n'
                                                                                    'Stop-Process '
                                                                                    '-ID '
                                                                                    '$myT1036\n',
                                                                         'elevation_required': False,
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
                                                                    '- windows '
                                                                    'exe '
                                                                    'running '
                                                                    'as '
                                                                    'different '
                                                                    'windows '
                                                                    'exe',
                                                            'supported_platforms': ['windows']},
                                                           {'description': 'Detect '
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
                                                                                            'C:\\T1036.txt '
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
                                                                                    'T1036 '
                                                                                    '> '
                                                                                    'C:\\T1036.txt\n',
                                                                         'elevation_required': True,
                                                                         'name': 'command_prompt'},
                                                            'name': 'Malicious '
                                                                    'process '
                                                                    'Masquerading '
                                                                    'as '
                                                                    'LSM.exe',
                                                            'supported_platforms': ['windows']}],
                                          'attack_technique': 'T1036',
                                          'display_name': 'Masquerading'}},
 {'Threat Hunting Tables': {'chain_id': '100002',
                            'commandline_string': '',
                            'file_path': '\\Recycle.bin',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100003',
                            'commandline_string': '',
                            'file_path': '\\Users\\All Users\\',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100004',
                            'commandline_string': '',
                            'file_path': '\\Users\\Default\\',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100005',
                            'commandline_string': '',
                            'file_path': '\\Users\\Public\\',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100006',
                            'commandline_string': '',
                            'file_path': '\\Perflogs\\',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100007',
                            'commandline_string': '',
                            'file_path': '\\config\\systemprofile\\',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100008',
                            'commandline_string': '',
                            'file_path': '\\Windows\\Fonts\\',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100009',
                            'commandline_string': '',
                            'file_path': '\\Windows\\IME\\',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100010',
                            'commandline_string': '',
                            'file_path': '\\Windows\\addins\\',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100011',
                            'commandline_string': '',
                            'file_path': '\\ProgramData\\',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': '*.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100021',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': 'csrsr.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100022',
                            'commandline_string': '',
                            'file_path': '!=*\\Windows\\System32\\',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': 'csrss.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100023',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': 'cssrss.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100033',
                            'commandline_string': '',
                            'file_path': '!=*\\Windows\\System32\\',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': 'explorer.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100035',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': 'iexplore.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100036',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': 'isass.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100037',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': 'lexplore.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100038',
                            'commandline_string': '',
                            'file_path': '!=*\\Windows\\System32\\',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': 'lsm.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100039',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': 'lssass.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100040',
                            'commandline_string': '',
                            'file_path': '!=*\\Windows\\System32\\',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': 'mmc.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100050',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': 'https://digital-forensics.sans.org/media/dfir_poster_2014.pdf',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': '!=wininit.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'lsass',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100071',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': 'run32dll.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100072',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': 'rundII.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100075',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': 'scvhost.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100077',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': 'smss.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100078',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': '!=services.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': 'svchost.exe',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100079',
                            'commandline_string': '',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1036',
                            'mitre_caption': 'masquerading',
                            'os': 'windows',
                            'parent_process': 'svchosts.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors


* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)

* [FIN7](../actors/FIN7.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Carbanak](../actors/Carbanak.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [Poseidon Group](../actors/Poseidon-Group.md)
    
* [admin@338](../actors/admin@338.md)
    
* [APT1](../actors/APT1.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [APT32](../actors/APT32.md)
    
* [Sowbug](../actors/Sowbug.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [FIN6](../actors/FIN6.md)
    
* [menuPass](../actors/menuPass.md)
    
* [Scarlet Mimic](../actors/Scarlet-Mimic.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [PLATINUM](../actors/PLATINUM.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [APT41](../actors/APT41.md)
    
