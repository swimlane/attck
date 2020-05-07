
# Data Encrypted

## Description

### MITRE Description

> Data is encrypted before being exfiltrated in order to hide the information that is being exfiltrated from detection or to make the exfiltration less conspicuous upon inspection by a defender. The encryption is performed by a utility, programming library, or custom algorithm on the data itself and is considered separate from any encryption performed by the command and control or file transfer protocol. Common file archive formats that can encrypt files are RAR and zip.

Other exfiltration techniques likely apply as well to transfer the information out of the network, such as [Exfiltration Over Command and Control Channel](https://attack.mitre.org/techniques/T1041) and [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1022

## Potential Commands

```
mkdir -p /tmp/T1022
cd /tmp/T1022; touch a b c d e f g
zip --password "#{encryption_password}" /tmp/T1022/#{test_file} ./*
echo "#{encryption_password}" | gpg --batch --yes --passphrase-fd 0 --output /tmp/T1022/#{test_file}.zip.gpg -c /tmp/T1022/#{test_file}.zip
ls -l /tmp/T1022

mkdir -p #{test_folder}
cd #{test_folder}; touch a b c d e f g
zip --password "#{encryption_password}" #{test_folder}/T1022 ./*
echo "#{encryption_password}" | gpg --batch --yes --passphrase-fd 0 --output #{test_folder}/T1022.zip.gpg -c #{test_folder}/T1022.zip
ls -l #{test_folder}

mkdir -p #{test_folder}
cd #{test_folder}; touch a b c d e f g
zip --password "InsertPasswordHere" #{test_folder}/#{test_file} ./*
echo "InsertPasswordHere" | gpg --batch --yes --passphrase-fd 0 --output #{test_folder}/#{test_file}.zip.gpg -c #{test_folder}/#{test_file}.zip
ls -l #{test_folder}

mkdir .\tmp\victim-files
cd .\tmp\victim-files
echo "This file will be encrypted" > .\encrypted_file.txt
rar a -hp"blue" hello.rar
dir

path=%path%;"C:\Program Files (x86)\winzip"
mkdir .\tmp\victim-files
cd .\tmp\victim-files
echo "This file will be encrypted" > .\encrypted_file.txt
"%ProgramFiles%\WinZip\winzip64.exe" -min -a -s"hello" archive.zip *
dir

path=%path%;"C:\Program Files (x86)\winzip"
mkdir .\tmp\victim-files
cd .\tmp\victim-files
echo "This file will be encrypted" > .\encrypted_file.txt
"#{winzip_exe}" -min -a -s"hello" archive.zip *
dir

path=%path%;"C:\Program Files (x86)\winzip"
mkdir .\tmp\victim-files
cd .\tmp\victim-files
echo "This file will be encrypted" > .\encrypted_file.txt
"#{winzip_exe}" -min -a -s"hello" archive.zip *
dir

mkdir $PathToAtomicsFolder\T1022\victim-files
cd $PathToAtomicsFolder\T1022\victim-files
echo "This file will be encrypted" > .\encrypted_file.txt
7z a archive.7z -pblue
dir

```

## Commands Dataset

```
[{'command': 'mkdir -p /tmp/T1022\n'
             'cd /tmp/T1022; touch a b c d e f g\n'
             'zip --password "#{encryption_password}" /tmp/T1022/#{test_file} '
             './*\n'
             'echo "#{encryption_password}" | gpg --batch --yes '
             '--passphrase-fd 0 --output /tmp/T1022/#{test_file}.zip.gpg -c '
             '/tmp/T1022/#{test_file}.zip\n'
             'ls -l /tmp/T1022\n',
  'name': None,
  'source': 'atomics/T1022/T1022.yaml'},
 {'command': 'mkdir -p #{test_folder}\n'
             'cd #{test_folder}; touch a b c d e f g\n'
             'zip --password "#{encryption_password}" #{test_folder}/T1022 '
             './*\n'
             'echo "#{encryption_password}" | gpg --batch --yes '
             '--passphrase-fd 0 --output #{test_folder}/T1022.zip.gpg -c '
             '#{test_folder}/T1022.zip\n'
             'ls -l #{test_folder}\n',
  'name': None,
  'source': 'atomics/T1022/T1022.yaml'},
 {'command': 'mkdir -p #{test_folder}\n'
             'cd #{test_folder}; touch a b c d e f g\n'
             'zip --password "InsertPasswordHere" #{test_folder}/#{test_file} '
             './*\n'
             'echo "InsertPasswordHere" | gpg --batch --yes --passphrase-fd 0 '
             '--output #{test_folder}/#{test_file}.zip.gpg -c '
             '#{test_folder}/#{test_file}.zip\n'
             'ls -l #{test_folder}\n',
  'name': None,
  'source': 'atomics/T1022/T1022.yaml'},
 {'command': 'mkdir .\\tmp\\victim-files\n'
             'cd .\\tmp\\victim-files\n'
             'echo "This file will be encrypted" > .\\encrypted_file.txt\n'
             'rar a -hp"blue" hello.rar\n'
             'dir\n',
  'name': None,
  'source': 'atomics/T1022/T1022.yaml'},
 {'command': 'path=%path%;"C:\\Program Files (x86)\\winzip"\n'
             'mkdir .\\tmp\\victim-files\n'
             'cd .\\tmp\\victim-files\n'
             'echo "This file will be encrypted" > .\\encrypted_file.txt\n'
             '"%ProgramFiles%\\WinZip\\winzip64.exe" -min -a -s"hello" '
             'archive.zip *\n'
             'dir\n',
  'name': None,
  'source': 'atomics/T1022/T1022.yaml'},
 {'command': 'path=%path%;"C:\\Program Files (x86)\\winzip"\n'
             'mkdir .\\tmp\\victim-files\n'
             'cd .\\tmp\\victim-files\n'
             'echo "This file will be encrypted" > .\\encrypted_file.txt\n'
             '"#{winzip_exe}" -min -a -s"hello" archive.zip *\n'
             'dir\n',
  'name': None,
  'source': 'atomics/T1022/T1022.yaml'},
 {'command': 'path=%path%;"C:\\Program Files (x86)\\winzip"\n'
             'mkdir .\\tmp\\victim-files\n'
             'cd .\\tmp\\victim-files\n'
             'echo "This file will be encrypted" > .\\encrypted_file.txt\n'
             '"#{winzip_exe}" -min -a -s"hello" archive.zip *\n'
             'dir\n',
  'name': None,
  'source': 'atomics/T1022/T1022.yaml'},
 {'command': 'mkdir $PathToAtomicsFolder\\T1022\\victim-files\n'
             'cd $PathToAtomicsFolder\\T1022\\victim-files\n'
             'echo "This file will be encrypted" > .\\encrypted_file.txt\n'
             '7z a archive.7z -pblue\n'
             'dir\n',
  'name': None,
  'source': 'atomics/T1022/T1022.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Data Encrypted': {'atomic_tests': [{'dependencies': [{'description': 'gpg '
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
                                                                                              '#{test_folder}\n',
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
                                                                                  'test_file': {'default': 'T1022',
                                                                                                'description': 'Temp '
                                                                                                               'file '
                                                                                                               'used '
                                                                                                               'to '
                                                                                                               'store '
                                                                                                               'encrypted '
                                                                                                               'data.',
                                                                                                'type': 'Path'},
                                                                                  'test_folder': {'default': '/tmp/T1022',
                                                                                                  'description': 'Path '
                                                                                                                 'used '
                                                                                                                 'to '
                                                                                                                 'store '
                                                                                                                 'files.',
                                                                                                  'type': 'Path'}},
                                                              'name': 'Data '
                                                                      'Encrypted '
                                                                      'with '
                                                                      'zip and '
                                                                      'gpg '
                                                                      'symmetric',
                                                              'supported_platforms': ['macos',
                                                                                      'linux']},
                                                             {'description': 'Note: '
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
                                                             {'dependencies': [{'description': 'Winzip '
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
                                                             {'description': 'Note: '
                                                                             'Requires '
                                                                             '7zip '
                                                                             'installation\n',
                                                              'executor': {'command': 'mkdir '
                                                                                      '$PathToAtomicsFolder\\T1022\\victim-files\n'
                                                                                      'cd '
                                                                                      '$PathToAtomicsFolder\\T1022\\victim-files\n'
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
                                                              'supported_platforms': ['windows']}],
                                            'attack_technique': 'T1022',
                                            'display_name': 'Data Encrypted'}}]
```

# Tactics


* [Exfiltration](../tactics/Exfiltration.md)


# Mitigations

None

# Actors


* [Ke3chang](../actors/Ke3chang.md)

* [Patchwork](../actors/Patchwork.md)
    
* [FIN6](../actors/FIN6.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [CopyKittens](../actors/CopyKittens.md)
    
* [Honeybee](../actors/Honeybee.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [APT32](../actors/APT32.md)
    
* [menuPass](../actors/menuPass.md)
    
* [Turla](../actors/Turla.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
