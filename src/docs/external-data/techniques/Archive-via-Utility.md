
# Archive via Utility

## Description

### MITRE Description

> An adversary may compress or encrypt data that is collected prior to exfiltration using 3rd party utilities. Many utilities exist that can archive data, including 7-Zip(Citation: 7zip Homepage), WinRAR(Citation: WinRAR Homepage), and WinZip(Citation: WinZip Homepage). Most utilities include functionality to encrypt and/or compress data.

Some 3rd party utilities may be preinstalled, such as `tar` on Linux and macOS or `zip` on Windows systems.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1560/001

## Potential Commands

```
zip #{output_file} $HOME/*.txt
mkdir -p #{test_folder}
cd #{test_folder}; touch a b c d e f g
zip --password "#{encryption_password}" #{test_folder}/T1560 ./*
echo "#{encryption_password}" | gpg --batch --yes --passphrase-fd 0 --output #{test_folder}/T1560.zip.gpg -c #{test_folder}/T1560.zip
ls -l #{test_folder}
path=%path%;"C:\Program Files (x86)\winzip"
mkdir .\tmp\victim-files
cd .\tmp\victim-files
echo "This file will be encrypted" > .\encrypted_file.txt
"%ProgramFiles%\WinZip\winzip64.exe" -min -a -s"hello" archive.zip *
dir
mkdir $PathToAtomicsFolder\T1560.001\victim-files
cd $PathToAtomicsFolder\T1560.001\victim-files
echo "This file will be encrypted" > .\encrypted_file.txt
7z a archive.7z -pblue
dir
test -e $HOME/victim-gzip.txt && gzip -k $HOME/victim-gzip.txt || (echo '#{input_content}' >> $HOME/victim-gzip.txt; gzip -k $HOME/victim-gzip.txt)
"#{rar_exe}" a -r #{output_file} #{input_path}\*#{file_extension}
mkdir .\tmp\victim-files
cd .\tmp\victim-files
echo "This file will be encrypted" > .\encrypted_file.txt
rar a -hp"blue" hello.rar
dir
tar -cvzf #{output_file} $HOME/$USERNAME
tar -cvzf $HOME/data.tar.gz #{input_file_folder}
"#{rar_exe}" a -r %USERPROFILE%\T1560.001-data.rar #{input_path}\*#{file_extension}
path=%path%;"C:\Program Files (x86)\winzip"
mkdir .\tmp\victim-files
cd .\tmp\victim-files
echo "This file will be encrypted" > .\encrypted_file.txt
"#{winzip_exe}" -min -a -s"hello" archive.zip *
dir
"#{rar_exe}" a -r #{output_file} %USERPROFILE%\*#{file_extension}
"%programfiles%/WinRAR/Rar.exe" a -r #{output_file} #{input_path}\*#{file_extension}
test -e #{input_file} && gzip -k #{input_file} || (echo 'confidential! SSN: 078-05-1120 - CCN: 4000 1234 5678 9101' >> #{input_file}; gzip -k #{input_file})
"#{rar_exe}" a -r #{output_file} #{input_path}\*.txt
mkdir -p #{test_folder}
cd #{test_folder}; touch a b c d e f g
zip --password "InsertPasswordHere" #{test_folder}/#{test_file} ./*
echo "InsertPasswordHere" | gpg --batch --yes --passphrase-fd 0 --output #{test_folder}/#{test_file}.zip.gpg -c #{test_folder}/#{test_file}.zip
ls -l #{test_folder}
mkdir -p /tmp/T1560
cd /tmp/T1560; touch a b c d e f g
zip --password "#{encryption_password}" /tmp/T1560/#{test_file} ./*
echo "#{encryption_password}" | gpg --batch --yes --passphrase-fd 0 --output /tmp/T1560/#{test_file}.zip.gpg -c /tmp/T1560/#{test_file}.zip
ls -l /tmp/T1560
zip $HOME/data.zip #{input_files}
```

## Commands Dataset

```
[{'command': '"#{rar_exe}" a -r #{output_file} '
             '%USERPROFILE%\\*#{file_extension}\n',
  'name': None,
  'source': 'atomics/T1560.001/T1560.001.yaml'},
 {'command': '"#{rar_exe}" a -r #{output_file} #{input_path}\\*.txt\n',
  'name': None,
  'source': 'atomics/T1560.001/T1560.001.yaml'},
 {'command': '"#{rar_exe}" a -r %USERPROFILE%\\T1560.001-data.rar '
             '#{input_path}\\*#{file_extension}\n',
  'name': None,
  'source': 'atomics/T1560.001/T1560.001.yaml'},
 {'command': '"#{rar_exe}" a -r #{output_file} '
             '#{input_path}\\*#{file_extension}\n',
  'name': None,
  'source': 'atomics/T1560.001/T1560.001.yaml'},
 {'command': '"%programfiles%/WinRAR/Rar.exe" a -r #{output_file} '
             '#{input_path}\\*#{file_extension}\n',
  'name': None,
  'source': 'atomics/T1560.001/T1560.001.yaml'},
 {'command': 'mkdir .\\tmp\\victim-files\n'
             'cd .\\tmp\\victim-files\n'
             'echo "This file will be encrypted" > .\\encrypted_file.txt\n'
             'rar a -hp"blue" hello.rar\n'
             'dir\n',
  'name': None,
  'source': 'atomics/T1560.001/T1560.001.yaml'},
 {'command': 'path=%path%;"C:\\Program Files (x86)\\winzip"\n'
             'mkdir .\\tmp\\victim-files\n'
             'cd .\\tmp\\victim-files\n'
             'echo "This file will be encrypted" > .\\encrypted_file.txt\n'
             '"%ProgramFiles%\\WinZip\\winzip64.exe" -min -a -s"hello" '
             'archive.zip *\n'
             'dir\n',
  'name': None,
  'source': 'atomics/T1560.001/T1560.001.yaml'},
 {'command': 'path=%path%;"C:\\Program Files (x86)\\winzip"\n'
             'mkdir .\\tmp\\victim-files\n'
             'cd .\\tmp\\victim-files\n'
             'echo "This file will be encrypted" > .\\encrypted_file.txt\n'
             '"#{winzip_exe}" -min -a -s"hello" archive.zip *\n'
             'dir\n',
  'name': None,
  'source': 'atomics/T1560.001/T1560.001.yaml'},
 {'command': 'path=%path%;"C:\\Program Files (x86)\\winzip"\n'
             'mkdir .\\tmp\\victim-files\n'
             'cd .\\tmp\\victim-files\n'
             'echo "This file will be encrypted" > .\\encrypted_file.txt\n'
             '"#{winzip_exe}" -min -a -s"hello" archive.zip *\n'
             'dir\n',
  'name': None,
  'source': 'atomics/T1560.001/T1560.001.yaml'},
 {'command': 'mkdir $PathToAtomicsFolder\\T1560.001\\victim-files\n'
             'cd $PathToAtomicsFolder\\T1560.001\\victim-files\n'
             'echo "This file will be encrypted" > .\\encrypted_file.txt\n'
             '7z a archive.7z -pblue\n'
             'dir\n',
  'name': None,
  'source': 'atomics/T1560.001/T1560.001.yaml'},
 {'command': 'zip #{output_file} $HOME/*.txt\n',
  'name': None,
  'source': 'atomics/T1560.001/T1560.001.yaml'},
 {'command': 'zip $HOME/data.zip #{input_files}\n',
  'name': None,
  'source': 'atomics/T1560.001/T1560.001.yaml'},
 {'command': 'test -e $HOME/victim-gzip.txt && gzip -k $HOME/victim-gzip.txt '
             "|| (echo '#{input_content}' >> $HOME/victim-gzip.txt; gzip -k "
             '$HOME/victim-gzip.txt)\n',
  'name': None,
  'source': 'atomics/T1560.001/T1560.001.yaml'},
 {'command': 'test -e #{input_file} && gzip -k #{input_file} || (echo '
             "'confidential! SSN: 078-05-1120 - CCN: 4000 1234 5678 9101' >> "
             '#{input_file}; gzip -k #{input_file})\n',
  'name': None,
  'source': 'atomics/T1560.001/T1560.001.yaml'},
 {'command': 'tar -cvzf #{output_file} $HOME/$USERNAME\n',
  'name': None,
  'source': 'atomics/T1560.001/T1560.001.yaml'},
 {'command': 'tar -cvzf $HOME/data.tar.gz #{input_file_folder}\n',
  'name': None,
  'source': 'atomics/T1560.001/T1560.001.yaml'},
 {'command': 'mkdir -p /tmp/T1560\n'
             'cd /tmp/T1560; touch a b c d e f g\n'
             'zip --password "#{encryption_password}" /tmp/T1560/#{test_file} '
             './*\n'
             'echo "#{encryption_password}" | gpg --batch --yes '
             '--passphrase-fd 0 --output /tmp/T1560/#{test_file}.zip.gpg -c '
             '/tmp/T1560/#{test_file}.zip\n'
             'ls -l /tmp/T1560\n',
  'name': None,
  'source': 'atomics/T1560.001/T1560.001.yaml'},
 {'command': 'mkdir -p #{test_folder}\n'
             'cd #{test_folder}; touch a b c d e f g\n'
             'zip --password "#{encryption_password}" #{test_folder}/T1560 '
             './*\n'
             'echo "#{encryption_password}" | gpg --batch --yes '
             '--passphrase-fd 0 --output #{test_folder}/T1560.zip.gpg -c '
             '#{test_folder}/T1560.zip\n'
             'ls -l #{test_folder}\n',
  'name': None,
  'source': 'atomics/T1560.001/T1560.001.yaml'},
 {'command': 'mkdir -p #{test_folder}\n'
             'cd #{test_folder}; touch a b c d e f g\n'
             'zip --password "InsertPasswordHere" #{test_folder}/#{test_file} '
             './*\n'
             'echo "InsertPasswordHere" | gpg --batch --yes --passphrase-fd 0 '
             '--output #{test_folder}/#{test_file}.zip.gpg -c '
             '#{test_folder}/#{test_file}.zip\n'
             'ls -l #{test_folder}\n',
  'name': None,
  'source': 'atomics/T1560.001/T1560.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Archive Collected Data: Archive via Utility': {'atomic_tests': [{'auto_generated_guid': '02ea31cb-3b4c-4a2d-9bf1-e4e70ebcf5d0',
                                                                                           'dependencies': [{'description': 'Rar '
                                                                                                                            'tool '
                                                                                                                            'must '
                                                                                                                            'be '
                                                                                                                            'installed '
                                                                                                                            'at '
                                                                                                                            'specified '
                                                                                                                            'location '
                                                                                                                            '(#{rar_exe})\n',
                                                                                                             'get_prereq_command': 'echo '
                                                                                                                                   'Downloading '
                                                                                                                                   'Winrar '
                                                                                                                                   'installer\n'
                                                                                                                                   'bitsadmin '
                                                                                                                                   '/transfer '
                                                                                                                                   'myDownloadJob '
                                                                                                                                   '/download '
                                                                                                                                   '/priority '
                                                                                                                                   'normal '
                                                                                                                                   '"https://www.win-rar.com/fileadmin/winrar-versions/winrar/th/winrar-x64-580.exe" '
                                                                                                                                   '#{rar_installer}\n'
                                                                                                                                   'echo '
                                                                                                                                   'Follow '
                                                                                                                                   'the '
                                                                                                                                   'installer '
                                                                                                                                   'prompts '
                                                                                                                                   'to '
                                                                                                                                   'install '
                                                                                                                                   'Winrar\n'
                                                                                                                                   '#{rar_installer}\n',
                                                                                                             'prereq_command': 'if '
                                                                                                                               'not '
                                                                                                                               'exist '
                                                                                                                               '"#{rar_exe}" '
                                                                                                                               '(exit '
                                                                                                                               '/b '
                                                                                                                               '1)\n'}],
                                                                                           'description': 'An '
                                                                                                          'adversary '
                                                                                                          'may '
                                                                                                          'compress '
                                                                                                          'data '
                                                                                                          '(e.g., '
                                                                                                          'sensitive '
                                                                                                          'documents) '
                                                                                                          'that '
                                                                                                          'is '
                                                                                                          'collected '
                                                                                                          'prior '
                                                                                                          'to '
                                                                                                          'exfiltration.\n'
                                                                                                          'When '
                                                                                                          'the '
                                                                                                          'test '
                                                                                                          'completes '
                                                                                                          'you '
                                                                                                          'should '
                                                                                                          'find '
                                                                                                          'the '
                                                                                                          'txt '
                                                                                                          'files '
                                                                                                          'from '
                                                                                                          'the '
                                                                                                          '%USERPROFILE% '
                                                                                                          'directory '
                                                                                                          'compressed '
                                                                                                          'in '
                                                                                                          'a '
                                                                                                          'file '
                                                                                                          'called '
                                                                                                          'T1560.001-data.rar '
                                                                                                          'in '
                                                                                                          'the '
                                                                                                          '%USERPROFILE% '
                                                                                                          'directory \n',
                                                                                           'executor': {'cleanup_command': 'del '
                                                                                                                           '/f '
                                                                                                                           '/q '
                                                                                                                           '/s '
                                                                                                                           '#{output_file} '
                                                                                                                           '>nul '
                                                                                                                           '2>&1\n',
                                                                                                        'command': '"#{rar_exe}" '
                                                                                                                   'a '
                                                                                                                   '-r '
                                                                                                                   '#{output_file} '
                                                                                                                   '#{input_path}\\*#{file_extension}\n',
                                                                                                        'elevation_required': False,
                                                                                                        'name': 'command_prompt'},
                                                                                           'input_arguments': {'file_extension': {'default': '.txt',
                                                                                                                                  'description': 'Extension '
                                                                                                                                                 'of '
                                                                                                                                                 'files '
                                                                                                                                                 'to '
                                                                                                                                                 'compress',
                                                                                                                                  'type': 'String'},
                                                                                                               'input_path': {'default': '%USERPROFILE%',
                                                                                                                              'description': 'Path '
                                                                                                                                             'that '
                                                                                                                                             'should '
                                                                                                                                             'be '
                                                                                                                                             'compressed '
                                                                                                                                             'into '
                                                                                                                                             'our '
                                                                                                                                             'output '
                                                                                                                                             'file',
                                                                                                                              'type': 'Path'},
                                                                                                               'output_file': {'default': '%USERPROFILE%\\T1560.001-data.rar',
                                                                                                                               'description': 'Path '
                                                                                                                                              'where '
                                                                                                                                              'resulting '
                                                                                                                                              'compressed '
                                                                                                                                              'data '
                                                                                                                                              'should '
                                                                                                                                              'be '
                                                                                                                                              'placed',
                                                                                                                               'type': 'Path'},
                                                                                                               'rar_exe': {'default': '%programfiles%/WinRAR/Rar.exe',
                                                                                                                           'description': 'The '
                                                                                                                                          'RAR '
                                                                                                                                          'executable '
                                                                                                                                          'from '
                                                                                                                                          'Winrar',
                                                                                                                           'type': 'Path'},
                                                                                                               'rar_installer': {'default': '%TEMP%\\winrar.exe',
                                                                                                                                 'description': 'Winrar '
                                                                                                                                                'installer',
                                                                                                                                 'type': 'Path'}},
                                                                                           'name': 'Compress '
                                                                                                   'Data '
                                                                                                   'for '
                                                                                                   'Exfiltration '
                                                                                                   'With '
                                                                                                   'Rar',
                                                                                           'supported_platforms': ['windows']},
                                                                                          {'auto_generated_guid': '8dd61a55-44c6-43cc-af0c-8bdda276860c',
                                                                                           'description': 'Note: '
                                                                                                          'Requires '
                                                                                                          'winrar '
                                                                                                          'installation\n'
                                                                                                          'rar '
                                                                                                          'a '
                                                                                                          '-p"blue" '
                                                                                                          'hello.rar '
                                                                                                          '(VARIANT)\n',
                                                                                           'executor': {'command': 'mkdir '
                                                                                                                   '.\\tmp\\victim-files\n'
                                                                                                                   'cd '
                                                                                                                   '.\\tmp\\victim-files\n'
                                                                                                                   'echo '
                                                                                                                   '"This '
                                                                                                                   'file '
                                                                                                                   'will '
                                                                                                                   'be '
                                                                                                                   'encrypted" '
                                                                                                                   '> '
                                                                                                                   '.\\encrypted_file.txt\n'
                                                                                                                   'rar '
                                                                                                                   'a '
                                                                                                                   '-hp"blue" '
                                                                                                                   'hello.rar\n'
                                                                                                                   'dir\n',
                                                                                                        'elevation_required': False,
                                                                                                        'name': 'command_prompt'},
                                                                                           'name': 'Compress '
                                                                                                   'Data '
                                                                                                   'and '
                                                                                                   'lock '
                                                                                                   'with '
                                                                                                   'password '
                                                                                                   'for '
                                                                                                   'Exfiltration '
                                                                                                   'with '
                                                                                                   'winrar',
                                                                                           'supported_platforms': ['windows']},
                                                                                          {'auto_generated_guid': '01df0353-d531-408d-a0c5-3161bf822134',
                                                                                           'dependencies': [{'description': 'Winzip '
                                                                                                                            'must '
                                                                                                                            'be '
                                                                                                                            'installed\n',
                                                                                                             'get_prereq_command': 'if(Invoke-WebRequestVerifyHash '
                                                                                                                                   '"#{winzip_url}" '
                                                                                                                                   '"$env:Temp\\winzip.exe" '
                                                                                                                                   '#{winzip_hash}){\n'
                                                                                                                                   '  '
                                                                                                                                   'Write-Host '
                                                                                                                                   'Follow '
                                                                                                                                   'the '
                                                                                                                                   'installation '
                                                                                                                                   'prompts '
                                                                                                                                   'to '
                                                                                                                                   'continue\n'
                                                                                                                                   '  '
                                                                                                                                   'cmd '
                                                                                                                                   '/c '
                                                                                                                                   '"$env:Temp\\winzip.exe"\n'
                                                                                                                                   '}\n',
                                                                                                             'prereq_command': 'cmd '
                                                                                                                               '/c '
                                                                                                                               "'if "
                                                                                                                               'not '
                                                                                                                               'exist '
                                                                                                                               '"#{winzip_exe}" '
                                                                                                                               '(echo '
                                                                                                                               '1) '
                                                                                                                               'else '
                                                                                                                               '(echo '
                                                                                                                               "0)'\n"}],
                                                                                           'dependency_executor_name': 'powershell',
                                                                                           'description': 'Note: '
                                                                                                          'Requires '
                                                                                                          'winzip '
                                                                                                          'installation\n'
                                                                                                          'wzzip '
                                                                                                          'sample.zip '
                                                                                                          '-s"blueblue" '
                                                                                                          '*.txt '
                                                                                                          '(VARIANT)\n',
                                                                                           'executor': {'command': 'path=%path%;"C:\\Program '
                                                                                                                   'Files '
                                                                                                                   '(x86)\\winzip"\n'
                                                                                                                   'mkdir '
                                                                                                                   '.\\tmp\\victim-files\n'
                                                                                                                   'cd '
                                                                                                                   '.\\tmp\\victim-files\n'
                                                                                                                   'echo '
                                                                                                                   '"This '
                                                                                                                   'file '
                                                                                                                   'will '
                                                                                                                   'be '
                                                                                                                   'encrypted" '
                                                                                                                   '> '
                                                                                                                   '.\\encrypted_file.txt\n'
                                                                                                                   '"#{winzip_exe}" '
                                                                                                                   '-min '
                                                                                                                   '-a '
                                                                                                                   '-s"hello" '
                                                                                                                   'archive.zip '
                                                                                                                   '*\n'
                                                                                                                   'dir\n',
                                                                                                        'elevation_required': False,
                                                                                                        'name': 'command_prompt'},
                                                                                           'input_arguments': {'winzip_exe': {'default': '%ProgramFiles%\\WinZip\\winzip64.exe',
                                                                                                                              'description': 'Path '
                                                                                                                                             'to '
                                                                                                                                             'installed '
                                                                                                                                             'Winzip '
                                                                                                                                             'executable',
                                                                                                                              'type': 'Path'},
                                                                                                               'winzip_hash': {'default': 'B59DB592B924E963C21DA8709417AC0504F6158CFCB12FE5536F4A0E0D57D7FB',
                                                                                                                               'description': 'File '
                                                                                                                                              'hash '
                                                                                                                                              'of '
                                                                                                                                              'the '
                                                                                                                                              'Windows '
                                                                                                                                              'Credential '
                                                                                                                                              'Editor '
                                                                                                                                              'zip '
                                                                                                                                              'file',
                                                                                                                               'type': 'String'},
                                                                                                               'winzip_url': {'default': 'https://download.winzip.com/gl/nkln/winzip24-home.exe',
                                                                                                                              'description': 'Path '
                                                                                                                                             'to '
                                                                                                                                             'download '
                                                                                                                                             'Windows '
                                                                                                                                             'Credential '
                                                                                                                                             'Editor '
                                                                                                                                             'zip '
                                                                                                                                             'file',
                                                                                                                              'type': 'url'}},
                                                                                           'name': 'Compress '
                                                                                                   'Data '
                                                                                                   'and '
                                                                                                   'lock '
                                                                                                   'with '
                                                                                                   'password '
                                                                                                   'for '
                                                                                                   'Exfiltration '
                                                                                                   'with '
                                                                                                   'winzip',
                                                                                           'supported_platforms': ['windows']},
                                                                                          {'auto_generated_guid': 'd1334303-59cb-4a03-8313-b3e24d02c198',
                                                                                           'description': 'Note: '
                                                                                                          'Requires '
                                                                                                          '7zip '
                                                                                                          'installation\n',
                                                                                           'executor': {'command': 'mkdir '
                                                                                                                   '$PathToAtomicsFolder\\T1560.001\\victim-files\n'
                                                                                                                   'cd '
                                                                                                                   '$PathToAtomicsFolder\\T1560.001\\victim-files\n'
                                                                                                                   'echo '
                                                                                                                   '"This '
                                                                                                                   'file '
                                                                                                                   'will '
                                                                                                                   'be '
                                                                                                                   'encrypted" '
                                                                                                                   '> '
                                                                                                                   '.\\encrypted_file.txt\n'
                                                                                                                   '7z '
                                                                                                                   'a '
                                                                                                                   'archive.7z '
                                                                                                                   '-pblue\n'
                                                                                                                   'dir\n',
                                                                                                        'elevation_required': False,
                                                                                                        'name': 'command_prompt'},
                                                                                           'name': 'Compress '
                                                                                                   'Data '
                                                                                                   'and '
                                                                                                   'lock '
                                                                                                   'with '
                                                                                                   'password '
                                                                                                   'for '
                                                                                                   'Exfiltration '
                                                                                                   'with '
                                                                                                   '7zip',
                                                                                           'supported_platforms': ['windows']},
                                                                                          {'auto_generated_guid': 'c51cec55-28dd-4ad2-9461-1eacbc82c3a0',
                                                                                           'dependencies': [{'description': 'Files '
                                                                                                                            'to '
                                                                                                                            'zip '
                                                                                                                            'must '
                                                                                                                            'exist '
                                                                                                                            '(#{input_files})\n',
                                                                                                             'get_prereq_command': 'echo '
                                                                                                                                   'Please '
                                                                                                                                   'set '
                                                                                                                                   'input_files '
                                                                                                                                   'argument '
                                                                                                                                   'to '
                                                                                                                                   'include '
                                                                                                                                   'files '
                                                                                                                                   'that '
                                                                                                                                   'exist\n',
                                                                                                             'prereq_command': 'if '
                                                                                                                               '[ '
                                                                                                                               '$(ls '
                                                                                                                               '#{input_files} '
                                                                                                                               '| '
                                                                                                                               'wc '
                                                                                                                               '-l) '
                                                                                                                               '> '
                                                                                                                               '0 '
                                                                                                                               ']; '
                                                                                                                               'then '
                                                                                                                               'exit '
                                                                                                                               '0; '
                                                                                                                               'else '
                                                                                                                               'exit '
                                                                                                                               '1; '
                                                                                                                               'fi;\n'}],
                                                                                           'description': 'An '
                                                                                                          'adversary '
                                                                                                          'may '
                                                                                                          'compress '
                                                                                                          'data '
                                                                                                          '(e.g., '
                                                                                                          'sensitive '
                                                                                                          'documents) '
                                                                                                          'that '
                                                                                                          'is '
                                                                                                          'collected '
                                                                                                          'prior '
                                                                                                          'to '
                                                                                                          'exfiltration. '
                                                                                                          'This '
                                                                                                          'test '
                                                                                                          'uses '
                                                                                                          'standard '
                                                                                                          'zip '
                                                                                                          'compression.\n',
                                                                                           'executor': {'cleanup_command': 'rm '
                                                                                                                           '-f '
                                                                                                                           '#{output_file}\n',
                                                                                                        'command': 'zip '
                                                                                                                   '#{output_file} '
                                                                                                                   '#{input_files}\n',
                                                                                                        'elevation_required': False,
                                                                                                        'name': 'sh'},
                                                                                           'input_arguments': {'input_files': {'default': '$HOME/*.txt',
                                                                                                                               'description': 'Path '
                                                                                                                                              'that '
                                                                                                                                              'should '
                                                                                                                                              'be '
                                                                                                                                              'compressed '
                                                                                                                                              'into '
                                                                                                                                              'our '
                                                                                                                                              'output '
                                                                                                                                              'file, '
                                                                                                                                              'may '
                                                                                                                                              'include '
                                                                                                                                              'wildcards',
                                                                                                                               'type': 'Path'},
                                                                                                               'output_file': {'default': '$HOME/data.zip',
                                                                                                                               'description': 'Path '
                                                                                                                                              'that '
                                                                                                                                              'should '
                                                                                                                                              'be '
                                                                                                                                              'output '
                                                                                                                                              'as '
                                                                                                                                              'a '
                                                                                                                                              'zip '
                                                                                                                                              'archive',
                                                                                                                               'type': 'Path'}},
                                                                                           'name': 'Data '
                                                                                                   'Compressed '
                                                                                                   '- '
                                                                                                   'nix '
                                                                                                   '- '
                                                                                                   'zip',
                                                                                           'supported_platforms': ['linux',
                                                                                                                   'macos']},
                                                                                          {'auto_generated_guid': 'cde3c2af-3485-49eb-9c1f-0ed60e9cc0af',
                                                                                           'description': 'An '
                                                                                                          'adversary '
                                                                                                          'may '
                                                                                                          'compress '
                                                                                                          'data '
                                                                                                          '(e.g., '
                                                                                                          'sensitive '
                                                                                                          'documents) '
                                                                                                          'that '
                                                                                                          'is '
                                                                                                          'collected '
                                                                                                          'prior '
                                                                                                          'to '
                                                                                                          'exfiltration. '
                                                                                                          'This '
                                                                                                          'test '
                                                                                                          'uses '
                                                                                                          'standard '
                                                                                                          'gzip '
                                                                                                          'compression.\n',
                                                                                           'executor': {'cleanup_command': 'rm '
                                                                                                                           '-f '
                                                                                                                           '#{input_file}.gz\n',
                                                                                                        'command': 'test '
                                                                                                                   '-e '
                                                                                                                   '#{input_file} '
                                                                                                                   '&& '
                                                                                                                   'gzip '
                                                                                                                   '-k '
                                                                                                                   '#{input_file} '
                                                                                                                   '|| '
                                                                                                                   '(echo '
                                                                                                                   "'#{input_content}' "
                                                                                                                   '>> '
                                                                                                                   '#{input_file}; '
                                                                                                                   'gzip '
                                                                                                                   '-k '
                                                                                                                   '#{input_file})\n',
                                                                                                        'elevation_required': False,
                                                                                                        'name': 'sh'},
                                                                                           'input_arguments': {'input_content': {'default': 'confidential! '
                                                                                                                                            'SSN: '
                                                                                                                                            '078-05-1120 '
                                                                                                                                            '- '
                                                                                                                                            'CCN: '
                                                                                                                                            '4000 '
                                                                                                                                            '1234 '
                                                                                                                                            '5678 '
                                                                                                                                            '9101',
                                                                                                                                 'description': 'contents '
                                                                                                                                                'of '
                                                                                                                                                'compressed '
                                                                                                                                                'files '
                                                                                                                                                'if '
                                                                                                                                                'file '
                                                                                                                                                'does '
                                                                                                                                                'not '
                                                                                                                                                'already '
                                                                                                                                                'exist. '
                                                                                                                                                'default '
                                                                                                                                                'contains '
                                                                                                                                                'test '
                                                                                                                                                'credit '
                                                                                                                                                'card '
                                                                                                                                                'and '
                                                                                                                                                'social '
                                                                                                                                                'security '
                                                                                                                                                'number',
                                                                                                                                 'type': 'String'},
                                                                                                               'input_file': {'default': '$HOME/victim-gzip.txt',
                                                                                                                              'description': 'Path '
                                                                                                                                             'that '
                                                                                                                                             'should '
                                                                                                                                             'be '
                                                                                                                                             'compressed',
                                                                                                                              'type': 'Path'}},
                                                                                           'name': 'Data '
                                                                                                   'Compressed '
                                                                                                   '- '
                                                                                                   'nix '
                                                                                                   '- '
                                                                                                   'gzip '
                                                                                                   'Single '
                                                                                                   'File',
                                                                                           'supported_platforms': ['linux',
                                                                                                                   'macos']},
                                                                                          {'auto_generated_guid': '7af2b51e-ad1c-498c-aca8-d3290c19535a',
                                                                                           'dependencies': [{'description': 'Folder '
                                                                                                                            'to '
                                                                                                                            'zip '
                                                                                                                            'must '
                                                                                                                            'exist '
                                                                                                                            '(#{input_file_folder})\n',
                                                                                                             'get_prereq_command': 'echo '
                                                                                                                                   'Please '
                                                                                                                                   'set '
                                                                                                                                   'input_file_folder '
                                                                                                                                   'argument '
                                                                                                                                   'to '
                                                                                                                                   'a '
                                                                                                                                   'folder '
                                                                                                                                   'that '
                                                                                                                                   'exists\n',
                                                                                                             'prereq_command': 'test '
                                                                                                                               '-e '
                                                                                                                               '#{input_file_folder}\n'}],
                                                                                           'description': 'An '
                                                                                                          'adversary '
                                                                                                          'may '
                                                                                                          'compress '
                                                                                                          'data '
                                                                                                          '(e.g., '
                                                                                                          'sensitive '
                                                                                                          'documents) '
                                                                                                          'that '
                                                                                                          'is '
                                                                                                          'collected '
                                                                                                          'prior '
                                                                                                          'to '
                                                                                                          'exfiltration. '
                                                                                                          'This '
                                                                                                          'test '
                                                                                                          'uses '
                                                                                                          'standard '
                                                                                                          'gzip '
                                                                                                          'compression.\n',
                                                                                           'executor': {'cleanup_command': 'rm '
                                                                                                                           '-f '
                                                                                                                           '#{output_file}\n',
                                                                                                        'command': 'tar '
                                                                                                                   '-cvzf '
                                                                                                                   '#{output_file} '
                                                                                                                   '#{input_file_folder}\n',
                                                                                                        'elevation_required': False,
                                                                                                        'name': 'sh'},
                                                                                           'input_arguments': {'input_file_folder': {'default': '$HOME/$USERNAME',
                                                                                                                                     'description': 'Path '
                                                                                                                                                    'that '
                                                                                                                                                    'should '
                                                                                                                                                    'be '
                                                                                                                                                    'compressed',
                                                                                                                                     'type': 'Path'},
                                                                                                               'output_file': {'default': '$HOME/data.tar.gz',
                                                                                                                               'description': 'File '
                                                                                                                                              'that '
                                                                                                                                              'should '
                                                                                                                                              'be '
                                                                                                                                              'output',
                                                                                                                               'type': 'Path'}},
                                                                                           'name': 'Data '
                                                                                                   'Compressed '
                                                                                                   '- '
                                                                                                   'nix '
                                                                                                   '- '
                                                                                                   'tar '
                                                                                                   'Folder '
                                                                                                   'or '
                                                                                                   'File',
                                                                                           'supported_platforms': ['linux',
                                                                                                                   'macos']},
                                                                                          {'auto_generated_guid': '0286eb44-e7ce-41a0-b109-3da516e05a5f',
                                                                                           'dependencies': [{'description': 'gpg '
                                                                                                                            'and '
                                                                                                                            'zip '
                                                                                                                            'are '
                                                                                                                            'required '
                                                                                                                            'to '
                                                                                                                            'run '
                                                                                                                            'the '
                                                                                                                            'test.',
                                                                                                             'get_prereq_command': 'echo '
                                                                                                                                   '"Install '
                                                                                                                                   'gpg '
                                                                                                                                   'and '
                                                                                                                                   'zip '
                                                                                                                                   'to '
                                                                                                                                   'run '
                                                                                                                                   'the '
                                                                                                                                   'test"; '
                                                                                                                                   'exit '
                                                                                                                                   '1;\n',
                                                                                                             'prereq_command': 'if '
                                                                                                                               '[ '
                                                                                                                               '! '
                                                                                                                               '-x '
                                                                                                                               '"$(command '
                                                                                                                               '-v '
                                                                                                                               'gpg)" '
                                                                                                                               '] '
                                                                                                                               '|| '
                                                                                                                               '[ '
                                                                                                                               '! '
                                                                                                                               '-x '
                                                                                                                               '"$(command '
                                                                                                                               '-v '
                                                                                                                               'zip)" '
                                                                                                                               ']; '
                                                                                                                               'then '
                                                                                                                               'exit '
                                                                                                                               '1; '
                                                                                                                               'fi;\n'}],
                                                                                           'dependency_executor_name': 'sh',
                                                                                           'description': 'Encrypt '
                                                                                                          'data '
                                                                                                          'for '
                                                                                                          'exiltration\n',
                                                                                           'executor': {'cleanup_command': 'rm '
                                                                                                                           '-Rf '
                                                                                                                           '#{test_folder}',
                                                                                                        'command': 'mkdir '
                                                                                                                   '-p '
                                                                                                                   '#{test_folder}\n'
                                                                                                                   'cd '
                                                                                                                   '#{test_folder}; '
                                                                                                                   'touch '
                                                                                                                   'a '
                                                                                                                   'b '
                                                                                                                   'c '
                                                                                                                   'd '
                                                                                                                   'e '
                                                                                                                   'f '
                                                                                                                   'g\n'
                                                                                                                   'zip '
                                                                                                                   '--password '
                                                                                                                   '"#{encryption_password}" '
                                                                                                                   '#{test_folder}/#{test_file} '
                                                                                                                   './*\n'
                                                                                                                   'echo '
                                                                                                                   '"#{encryption_password}" '
                                                                                                                   '| '
                                                                                                                   'gpg '
                                                                                                                   '--batch '
                                                                                                                   '--yes '
                                                                                                                   '--passphrase-fd '
                                                                                                                   '0 '
                                                                                                                   '--output '
                                                                                                                   '#{test_folder}/#{test_file}.zip.gpg '
                                                                                                                   '-c '
                                                                                                                   '#{test_folder}/#{test_file}.zip\n'
                                                                                                                   'ls '
                                                                                                                   '-l '
                                                                                                                   '#{test_folder}\n',
                                                                                                        'elevation_required': False,
                                                                                                        'name': 'sh'},
                                                                                           'input_arguments': {'encryption_password': {'default': 'InsertPasswordHere',
                                                                                                                                       'description': 'Password '
                                                                                                                                                      'used '
                                                                                                                                                      'to '
                                                                                                                                                      'encrypt '
                                                                                                                                                      'data.',
                                                                                                                                       'type': 'string'},
                                                                                                               'test_file': {'default': 'T1560',
                                                                                                                             'description': 'Temp '
                                                                                                                                            'file '
                                                                                                                                            'used '
                                                                                                                                            'to '
                                                                                                                                            'store '
                                                                                                                                            'encrypted '
                                                                                                                                            'data.',
                                                                                                                             'type': 'Path'},
                                                                                                               'test_folder': {'default': '/tmp/T1560',
                                                                                                                               'description': 'Path '
                                                                                                                                              'used '
                                                                                                                                              'to '
                                                                                                                                              'store '
                                                                                                                                              'files.',
                                                                                                                               'type': 'Path'}},
                                                                                           'name': 'Data '
                                                                                                   'Encrypted '
                                                                                                   'with '
                                                                                                   'zip '
                                                                                                   'and '
                                                                                                   'gpg '
                                                                                                   'symmetric',
                                                                                           'supported_platforms': ['macos',
                                                                                                                   'linux']}],
                                                                         'attack_technique': 'T1560.001',
                                                                         'display_name': 'Archive '
                                                                                         'Collected '
                                                                                         'Data: '
                                                                                         'Archive '
                                                                                         'via '
                                                                                         'Utility'}}]
```

# Tactics


* [Collection](../tactics/Collection.md)


# Mitigations


* [Audit](../mitigations/Audit.md)


# Actors


* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)

* [Ke3chang](../actors/Ke3chang.md)
    
* [CopyKittens](../actors/CopyKittens.md)
    
* [APT1](../actors/APT1.md)
    
* [FIN8](../actors/FIN8.md)
    
* [Sowbug](../actors/Sowbug.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [APT3](../actors/APT3.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [menuPass](../actors/menuPass.md)
    
* [APT39](../actors/APT39.md)
    
* [APT33](../actors/APT33.md)
    
* [Gallmaker](../actors/Gallmaker.md)
    
* [Turla](../actors/Turla.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [APT41](../actors/APT41.md)
    
