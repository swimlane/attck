
# Hidden Files and Directories

## Description

### MITRE Description

> To prevent normal users from accidentally changing special files on a system, most operating systems have the concept of a ‘hidden’ file. These files don’t show up when a user browses the file system with a GUI or when using normal commands on the command line. Users must explicitly ask to show the hidden files either via a series of Graphical User Interface (GUI) prompts or with command line switches (<code>dir /a</code> for Windows and <code>ls –a</code> for Linux and macOS).

Adversaries can use this to their advantage to hide files and folders anywhere on the system for persistence and evading a typical user or system analysis that does not incorporate investigation of hidden files.

### Windows

Users can mark specific files as hidden by using the attrib.exe binary. Simply do <code>attrib +h filename</code> to mark a file or folder as hidden. Similarly, the “+s” marks a file as a system file and the “+r” flag marks the file as read only. Like most windows binaries, the attrib.exe binary provides the ability to apply these changes recursively “/S”.

### Linux/Mac

Users can mark specific files as hidden simply by putting a “.” as the first character in the file or folder name  (Citation: Sofacy Komplex Trojan) (Citation: Antiquated Mac Malware). Files and folder that start with a period, ‘.’, are by default hidden from being viewed in the Finder application and standard command-line utilities like “ls”. Users must specifically change settings to have these files viewable. For command line usages, there is typically a flag to see all files (including hidden ones). To view these files in the Finder Application, the following command must be executed: <code>defaults write com.apple.finder AppleShowAllFiles YES</code>, and then relaunch the Finder Application.

### Mac

Files on macOS can be marked with the UF_HIDDEN flag which prevents them from being seen in Finder.app, but still allows them to be seen in Terminal.app (Citation: WireLurker).
Many applications create these hidden files and folders to store information so that it doesn’t clutter up the user’s workspace. For example, SSH utilities create a .ssh folder that’s hidden and contains the user’s known hosts and keys.

## Additional Attributes

* Bypass: ['Host forensic analysis']
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1158

## Potential Commands

```
mkdir /var/tmp/.hidden-directory
echo "T1158" > /var/tmp/.hidden-directory/.hidden-file

xattr -lr * / 2>&1 /dev/null | grep -C 2 "00 00 00 00 00 00 00 00 40 00 FF FF FF FF 00 00"

attrib.exe +s %temp%\T1158.txt

attrib.exe +h %temp%\T1158.txt

setfile -a V /tmp/evil

touch /var/tmp/T1158_mac.txt
chflags hidden /var/tmp/T1158_mac.txt

defaults write com.apple.finder AppleShowAllFiles YES

echo cmd /c echo "Shell code execution."> %temp%\T1158_has_ads_cmd.txt:#{ads_filename}
for /f "usebackq delims=" %i in (%temp%\T1158_has_ads_cmd.txt:#{ads_filename}) do %i

echo cmd /c echo "Shell code execution."> #{file_name}:adstest.txt
for /f "usebackq delims=" %i in (#{file_name}:adstest.txt) do %i

echo "test" > $env:TEMP\T1158_has_ads_powershell.txt | set-content -path test.txt -stream #{ads_filename} -value "test"
set-content -path $env:TEMP\T1158_has_ads_powershell.txt -stream #{ads_filename} -value "test2"
set-content -path . -stream #{ads_filename} -value "test3"

echo "test" > #{file_name} | set-content -path test.txt -stream adstest.txt -value "test"
set-content -path #{file_name} -stream adstest.txt -value "test2"
set-content -path . -stream adstest.txt -value "test3"

attrib.exe +s +h * appdata
```
mkdir .hidden-directory
```
```
mv file to a .file
```
```

## Commands Dataset

```
[{'command': 'mkdir /var/tmp/.hidden-directory\n'
             'echo "T1158" > /var/tmp/.hidden-directory/.hidden-file\n',
  'name': None,
  'source': 'atomics/T1158/T1158.yaml'},
 {'command': 'xattr -lr * / 2>&1 /dev/null | grep -C 2 "00 00 00 00 00 00 00 '
             '00 40 00 FF FF FF FF 00 00"\n',
  'name': None,
  'source': 'atomics/T1158/T1158.yaml'},
 {'command': 'attrib.exe +s %temp%\\T1158.txt\n',
  'name': None,
  'source': 'atomics/T1158/T1158.yaml'},
 {'command': 'attrib.exe +h %temp%\\T1158.txt\n',
  'name': None,
  'source': 'atomics/T1158/T1158.yaml'},
 {'command': 'setfile -a V /tmp/evil\n',
  'name': None,
  'source': 'atomics/T1158/T1158.yaml'},
 {'command': 'touch /var/tmp/T1158_mac.txt\n'
             'chflags hidden /var/tmp/T1158_mac.txt\n',
  'name': None,
  'source': 'atomics/T1158/T1158.yaml'},
 {'command': 'defaults write com.apple.finder AppleShowAllFiles YES\n',
  'name': None,
  'source': 'atomics/T1158/T1158.yaml'},
 {'command': 'echo cmd /c echo "Shell code execution."> '
             '%temp%\\T1158_has_ads_cmd.txt:#{ads_filename}\n'
             'for /f "usebackq delims=" %i in '
             '(%temp%\\T1158_has_ads_cmd.txt:#{ads_filename}) do %i\n',
  'name': None,
  'source': 'atomics/T1158/T1158.yaml'},
 {'command': 'echo cmd /c echo "Shell code execution."> '
             '#{file_name}:adstest.txt\n'
             'for /f "usebackq delims=" %i in (#{file_name}:adstest.txt) do '
             '%i\n',
  'name': None,
  'source': 'atomics/T1158/T1158.yaml'},
 {'command': 'echo "test" > $env:TEMP\\T1158_has_ads_powershell.txt | '
             'set-content -path test.txt -stream #{ads_filename} -value '
             '"test"\n'
             'set-content -path $env:TEMP\\T1158_has_ads_powershell.txt '
             '-stream #{ads_filename} -value "test2"\n'
             'set-content -path . -stream #{ads_filename} -value "test3"\n',
  'name': None,
  'source': 'atomics/T1158/T1158.yaml'},
 {'command': 'echo "test" > #{file_name} | set-content -path test.txt -stream '
             'adstest.txt -value "test"\n'
             'set-content -path #{file_name} -stream adstest.txt -value '
             '"test2"\n'
             'set-content -path . -stream adstest.txt -value "test3"\n',
  'name': None,
  'source': 'atomics/T1158/T1158.yaml'},
 {'command': 'attrib.exe +s +h * appdata',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': 'mkdir .hidden-directory',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': 'mv file to a .file',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'}]
```

## Potential Detections

```json
[{'data_source': 'bash_history logs'},
 {'data_source': 'find the hidden files/dirs from certain directory paths like '
                 '(/home/$user) and dump it to a location and ingest the file '
                 'and look for any malicious hidden files (scripted input to '
                 'the Splunk)'},
 {'data_source': {'author': 'Sami Ruohonen',
                  'description': 'Detects usage of attrib.exe to hide files '
                                 'from users.',
                  'detection': {'condition': 'selection and not (ini or intel)',
                                'ini': {'CommandLine': '*\\desktop.ini *'},
                                'intel': {'CommandLine': '+R +H +S +A '
                                                         '\\\\*.cui',
                                          'ParentCommandLine': 'C:\\WINDOWS\\system32\\\\*.bat',
                                          'ParentImage': '*\\cmd.exe'},
                                'selection': {'CommandLine': '* +h *',
                                              'Image': '*\\attrib.exe'}},
                  'falsepositives': ['igfxCUIService.exe hiding *.cui files '
                                     'via .bat script (attrib.exe a child of '
                                     'cmd.exe and igfxCUIService.exe is the '
                                     'parent of the cmd.exe)',
                                     'msiexec.exe hiding desktop.ini'],
                  'fields': ['CommandLine', 'ParentCommandLine', 'User'],
                  'id': '4281cb20-2994-4580-aa63-c8b86d019934',
                  'level': 'low',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'status': 'experimental',
                  'tags': ['attack.defense_evasion',
                           'attack.persistence',
                           'attack.t1158'],
                  'title': 'Hiding files with attrib.exe'}}]
```

## Potential Queries

```json
[{'name': 'Hidden Files And Directories',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and process_path contains '
           '"attrib.exe"and (process_command_line contains "+h"or '
           'process_command_line contains "+s")'},
 {'name': 'Hidden Files And Directories VSS',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1and (process_path contains '
           '"*\\\\VolumeShadowCopy*\\\\*"or process_command_line contains '
           '"*\\\\VolumeShadowCopy*\\\\*")'},
 {'name': None,
  'product': 'Splunk',
  'query': 'There are 2 ways by which we can capture this'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=bash_history bash_command="mkdir .*" | '
           'table host,user_name,bash_command'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=bash_history bash_command="mv * .*" | table '
           'host,user_name,bash_command'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'find_hidden_files.sh script can be run on a regular interval and '
           'check for any suspecious file creation. A whitelist can be craeted '
           'to filter out the standard hidden files/directories in a linux '
           'system.'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None, 'product': 'Splunk', 'query': 'find /home/ -name ".*"'},
 {'name': None, 'product': 'Splunk', 'query': 'find /home/ -type d -name ".*"'},
 {'name': None, 'product': 'Splunk', 'query': 'find /home/ -type f -name ".*"'},
 {'name': None, 'product': 'Splunk', 'query': '```'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Hidden Files and Directories': {'atomic_tests': [{'description': 'Creates '
                                                                                           'a '
                                                                                           'hidden '
                                                                                           'file '
                                                                                           'inside '
                                                                                           'a '
                                                                                           'hidden '
                                                                                           'directory\n',
                                                                            'executor': {'cleanup_command': 'rm '
                                                                                                            '-rf '
                                                                                                            '/var/tmp/.hidden-directory/\n',
                                                                                         'command': 'mkdir '
                                                                                                    '/var/tmp/.hidden-directory\n'
                                                                                                    'echo '
                                                                                                    '"T1158" '
                                                                                                    '> '
                                                                                                    '/var/tmp/.hidden-directory/.hidden-file\n',
                                                                                         'elevation_required': False,
                                                                                         'name': 'sh'},
                                                                            'name': 'Create '
                                                                                    'a '
                                                                                    'hidden '
                                                                                    'file '
                                                                                    'in '
                                                                                    'a '
                                                                                    'hidden '
                                                                                    'directory',
                                                                            'supported_platforms': ['linux',
                                                                                                    'macos']},
                                                                           {'description': 'Hide '
                                                                                           'a '
                                                                                           'file '
                                                                                           'on '
                                                                                           'MacOS\n',
                                                                            'executor': {'command': 'xattr '
                                                                                                    '-lr '
                                                                                                    '* '
                                                                                                    '/ '
                                                                                                    '2>&1 '
                                                                                                    '/dev/null '
                                                                                                    '| '
                                                                                                    'grep '
                                                                                                    '-C '
                                                                                                    '2 '
                                                                                                    '"00 '
                                                                                                    '00 '
                                                                                                    '00 '
                                                                                                    '00 '
                                                                                                    '00 '
                                                                                                    '00 '
                                                                                                    '00 '
                                                                                                    '00 '
                                                                                                    '40 '
                                                                                                    '00 '
                                                                                                    'FF '
                                                                                                    'FF '
                                                                                                    'FF '
                                                                                                    'FF '
                                                                                                    '00 '
                                                                                                    '00"\n',
                                                                                         'elevation_required': False,
                                                                                         'name': 'sh'},
                                                                            'name': 'Mac '
                                                                                    'Hidden '
                                                                                    'file',
                                                                            'supported_platforms': ['macos']},
                                                                           {'dependencies': [{'description': 'The '
                                                                                                             'file '
                                                                                                             'must '
                                                                                                             'exist '
                                                                                                             'on '
                                                                                                             'disk '
                                                                                                             'at '
                                                                                                             'specified '
                                                                                                             'location '
                                                                                                             '(#{file_to_modify})\n',
                                                                                              'get_prereq_command': 'echo '
                                                                                                                    'system_Attrib_T1158 '
                                                                                                                    '>> '
                                                                                                                    '#{file_to_modify}\n',
                                                                                              'prereq_command': 'IF '
                                                                                                                'EXIST '
                                                                                                                '#{file_to_modify} '
                                                                                                                '( '
                                                                                                                'EXIT '
                                                                                                                '0 '
                                                                                                                ') '
                                                                                                                'ELSE '
                                                                                                                '( '
                                                                                                                'EXIT '
                                                                                                                '1 '
                                                                                                                ')\n'}],
                                                                            'dependency_executor_name': 'command_prompt',
                                                                            'description': 'Creates '
                                                                                           'a '
                                                                                           'file '
                                                                                           'and '
                                                                                           'marks '
                                                                                           'it '
                                                                                           'as '
                                                                                           'a '
                                                                                           'system '
                                                                                           'file '
                                                                                           'using '
                                                                                           'the '
                                                                                           'attrib.exe '
                                                                                           'utility. '
                                                                                           'Upon '
                                                                                           'execution, '
                                                                                           'open '
                                                                                           'the '
                                                                                           'file '
                                                                                           'in '
                                                                                           'file '
                                                                                           'explorer '
                                                                                           'then '
                                                                                           'open '
                                                                                           'Properties '
                                                                                           '> '
                                                                                           'Details\n'
                                                                                           'and '
                                                                                           'observe '
                                                                                           'that '
                                                                                           'the '
                                                                                           'Attributes '
                                                                                           'are '
                                                                                           '"SA" '
                                                                                           'for '
                                                                                           'System '
                                                                                           'and '
                                                                                           'Archive.\n',
                                                                            'executor': {'cleanup_command': 'del '
                                                                                                            '/A:S '
                                                                                                            '#{file_to_modify} '
                                                                                                            '>nul '
                                                                                                            '2>&1\n',
                                                                                         'command': 'attrib.exe '
                                                                                                    '+s '
                                                                                                    '#{file_to_modify}\n',
                                                                                         'elevation_required': True,
                                                                                         'name': 'command_prompt'},
                                                                            'input_arguments': {'file_to_modify': {'default': '%temp%\\T1158.txt',
                                                                                                                   'description': 'File '
                                                                                                                                  'to '
                                                                                                                                  'modify '
                                                                                                                                  'using '
                                                                                                                                  'Attrib '
                                                                                                                                  'command',
                                                                                                                   'type': 'string'}},
                                                                            'name': 'Create '
                                                                                    'Windows '
                                                                                    'System '
                                                                                    'File '
                                                                                    'with '
                                                                                    'Attrib',
                                                                            'supported_platforms': ['windows']},
                                                                           {'dependencies': [{'description': 'The '
                                                                                                             'file '
                                                                                                             'must '
                                                                                                             'exist '
                                                                                                             'on '
                                                                                                             'disk '
                                                                                                             'at '
                                                                                                             'specified '
                                                                                                             'location '
                                                                                                             '(#{file_to_modify})\n',
                                                                                              'get_prereq_command': 'echo '
                                                                                                                    'system_Attrib_T1158 '
                                                                                                                    '>> '
                                                                                                                    '#{file_to_modify}\n',
                                                                                              'prereq_command': 'IF '
                                                                                                                'EXIST '
                                                                                                                '#{file_to_modify} '
                                                                                                                '( '
                                                                                                                'EXIT '
                                                                                                                '0 '
                                                                                                                ') '
                                                                                                                'ELSE '
                                                                                                                '( '
                                                                                                                'EXIT '
                                                                                                                '1 '
                                                                                                                ')\n'}],
                                                                            'dependency_executor_name': 'command_prompt',
                                                                            'description': 'Creates '
                                                                                           'a '
                                                                                           'file '
                                                                                           'and '
                                                                                           'marks '
                                                                                           'it '
                                                                                           'as '
                                                                                           'hidden '
                                                                                           'using '
                                                                                           'the '
                                                                                           'attrib.exe '
                                                                                           'utility.Upon '
                                                                                           'execution, '
                                                                                           'open '
                                                                                           'File '
                                                                                           'Epxplorer '
                                                                                           'and '
                                                                                           'enable '
                                                                                           'View '
                                                                                           '> '
                                                                                           'Hidden '
                                                                                           'Items. '
                                                                                           'Then, '
                                                                                           'open '
                                                                                           'Properties '
                                                                                           '> '
                                                                                           'Details '
                                                                                           'on '
                                                                                           'the '
                                                                                           'file\n'
                                                                                           'and '
                                                                                           'observe '
                                                                                           'that '
                                                                                           'the '
                                                                                           'Attributes '
                                                                                           'are '
                                                                                           '"SH" '
                                                                                           'for '
                                                                                           'System '
                                                                                           'and '
                                                                                           'Hidden.\n',
                                                                            'executor': {'cleanup_command': 'del '
                                                                                                            '/A:H '
                                                                                                            '#{file_to_modify} '
                                                                                                            '>nul '
                                                                                                            '2>&1\n',
                                                                                         'command': 'attrib.exe '
                                                                                                    '+h '
                                                                                                    '#{file_to_modify}\n',
                                                                                         'elevation_required': True,
                                                                                         'name': 'command_prompt'},
                                                                            'input_arguments': {'file_to_modify': {'default': '%temp%\\T1158.txt',
                                                                                                                   'description': 'File '
                                                                                                                                  'to '
                                                                                                                                  'modify '
                                                                                                                                  'using '
                                                                                                                                  'Attrib '
                                                                                                                                  'command',
                                                                                                                   'type': 'string'}},
                                                                            'name': 'Create '
                                                                                    'Windows '
                                                                                    'Hidden '
                                                                                    'File '
                                                                                    'with '
                                                                                    'Attrib',
                                                                            'supported_platforms': ['windows']},
                                                                           {'description': 'Requires '
                                                                                           'Apple '
                                                                                           'Dev '
                                                                                           'Tools\n',
                                                                            'executor': {'command': 'setfile '
                                                                                                    '-a '
                                                                                                    'V '
                                                                                                    '#{filename}\n',
                                                                                         'elevation_required': False,
                                                                                         'name': 'sh'},
                                                                            'input_arguments': {'filename': {'default': '/tmp/evil',
                                                                                                             'description': 'path '
                                                                                                                            'of '
                                                                                                                            'file '
                                                                                                                            'to '
                                                                                                                            'hide',
                                                                                                             'type': 'path'}},
                                                                            'name': 'Hidden '
                                                                                    'files',
                                                                            'supported_platforms': ['macos']},
                                                                           {'description': 'Hide '
                                                                                           'a '
                                                                                           'directory '
                                                                                           'on '
                                                                                           'MacOS\n',
                                                                            'executor': {'cleanup_command': 'rm '
                                                                                                            '/var/tmp/T1158_mac.txt\n',
                                                                                         'command': 'touch '
                                                                                                    '/var/tmp/T1158_mac.txt\n'
                                                                                                    'chflags '
                                                                                                    'hidden '
                                                                                                    '/var/tmp/T1158_mac.txt\n',
                                                                                         'elevation_required': False,
                                                                                         'name': 'sh'},
                                                                            'name': 'Hide '
                                                                                    'a '
                                                                                    'Directory',
                                                                            'supported_platforms': ['macos']},
                                                                           {'description': 'Show '
                                                                                           'all '
                                                                                           'hidden '
                                                                                           'files '
                                                                                           'on '
                                                                                           'MacOS\n',
                                                                            'executor': {'cleanup_command': 'defaults '
                                                                                                            'write '
                                                                                                            'com.apple.finder '
                                                                                                            'AppleShowAllFiles '
                                                                                                            'NO\n',
                                                                                         'command': 'defaults '
                                                                                                    'write '
                                                                                                    'com.apple.finder '
                                                                                                    'AppleShowAllFiles '
                                                                                                    'YES\n',
                                                                                         'elevation_required': False,
                                                                                         'name': 'sh'},
                                                                            'name': 'Show '
                                                                                    'all '
                                                                                    'hidden '
                                                                                    'files',
                                                                            'supported_platforms': ['macos']},
                                                                           {'dependencies': [{'description': 'The '
                                                                                                             'file '
                                                                                                             'must '
                                                                                                             'exist '
                                                                                                             'on '
                                                                                                             'disk '
                                                                                                             'at '
                                                                                                             'specified '
                                                                                                             'location '
                                                                                                             '(#{file_name})\n',
                                                                                              'get_prereq_command': 'echo '
                                                                                                                    'normal_text '
                                                                                                                    '>> '
                                                                                                                    '#{file_name} '
                                                                                                                    '>nul '
                                                                                                                    '2>&1\n',
                                                                                              'prereq_command': 'IF '
                                                                                                                'EXIST '
                                                                                                                '#{file_name} '
                                                                                                                '( '
                                                                                                                'EXIT '
                                                                                                                '0 '
                                                                                                                ') '
                                                                                                                'ELSE '
                                                                                                                '( '
                                                                                                                'EXIT '
                                                                                                                '1 '
                                                                                                                ')\n'}],
                                                                            'dependency_executor_name': 'command_prompt',
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
                                                                                           'T1158_has_ads.txt:adstest.txt"\n',
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
                                                                                                    'delims=φ" '
                                                                                                    '%i '
                                                                                                    'in '
                                                                                                    '(#{file_name}:#{ads_filename}) '
                                                                                                    'do '
                                                                                                    '%i\n',
                                                                                         'elevation_required': False,
                                                                                         'name': 'command_prompt'},
                                                                            'input_arguments': {'ads_filename': {'default': 'adstest.txt',
                                                                                                                 'description': 'Name '
                                                                                                                                'of '
                                                                                                                                'ADS '
                                                                                                                                'file.',
                                                                                                                 'type': 'string'},
                                                                                                'file_name': {'default': '%temp%\\T1158_has_ads_cmd.txt',
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
                                                                           {'dependencies': [{'description': 'The '
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
                                                                                           'T1158_has_ads_powershell.txt:adstest.txt" '
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
                                                                                         'elevation_required': False,
                                                                                         'name': 'powershell'},
                                                                            'input_arguments': {'ads_filename': {'default': 'adstest.txt',
                                                                                                                 'description': 'Name '
                                                                                                                                'of '
                                                                                                                                'ADS '
                                                                                                                                'file.',
                                                                                                                 'type': 'string'},
                                                                                                'file_name': {'default': '$env:TEMP\\T1158_has_ads_powershell.txt',
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
                                                          'attack_technique': 'T1158',
                                                          'display_name': 'Hidden '
                                                                          'Files '
                                                                          'and '
                                                                          'Directories'}},
 {'Threat Hunting Tables': {'chain_id': '100207',
                            'commandline_string': '+s +h * appdata',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '62b623a8dd6f7bfa7d1cff7b9db19f948840f36bee5c9063eaf5b898beb23c68',
                            'loaded_dll': '',
                            'mitre_attack': 'T1158',
                            'mitre_caption': 'hidden_files_dirs',
                            'os': 'windows',
                            'parent_process': 'attrib.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Persistence](../tactics/Persistence.md)
    

# Mitigations

None

# Actors


* [APT28](../actors/APT28.md)

* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [APT32](../actors/APT32.md)
    
