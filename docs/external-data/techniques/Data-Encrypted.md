
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
mkdir /tmp/victim-files
cd /tmp/victim-files
touch a b c d e f g
echo "creating zip with password 'insert password here'"
zip --password "insert password here" ./victim-files.zip ./*
echo "encrypting file with gpg, you will need to provide a password"
gpg -c /tmp/victim-files/victim-filex.zip
#<enter passphrase and confirm>
ls -l

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
[{'command': 'mkdir /tmp/victim-files\n'
             'cd /tmp/victim-files\n'
             'touch a b c d e f g\n'
             'echo "creating zip with password \'insert password here\'"\n'
             'zip --password "insert password here" ./victim-files.zip ./*\n'
             'echo "encrypting file with gpg, you will need to provide a '
             'password"\n'
             'gpg -c /tmp/victim-files/victim-filex.zip\n'
             '#<enter passphrase and confirm>\n'
             'ls -l\n',
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
[{'Atomic Red Team Test - Data Encrypted': {'atomic_tests': [{'description': 'Encrypt '
                                                                             'data '
                                                                             'for '
                                                                             'exiltration\n',
                                                              'executor': {'cleanup_command': 'rm '
                                                                                              '-Rf '
                                                                                              '/tmp/victim-files\n',
                                                                           'command': 'mkdir '
                                                                                      '/tmp/victim-files\n'
                                                                                      'cd '
                                                                                      '/tmp/victim-files\n'
                                                                                      'touch '
                                                                                      'a '
                                                                                      'b '
                                                                                      'c '
                                                                                      'd '
                                                                                      'e '
                                                                                      'f '
                                                                                      'g\n'
                                                                                      'echo '
                                                                                      '"creating '
                                                                                      'zip '
                                                                                      'with '
                                                                                      'password '
                                                                                      "'insert "
                                                                                      'password '
                                                                                      'here\'"\n'
                                                                                      'zip '
                                                                                      '--password '
                                                                                      '"insert '
                                                                                      'password '
                                                                                      'here" '
                                                                                      './victim-files.zip '
                                                                                      './*\n'
                                                                                      'echo '
                                                                                      '"encrypting '
                                                                                      'file '
                                                                                      'with '
                                                                                      'gpg, '
                                                                                      'you '
                                                                                      'will '
                                                                                      'need '
                                                                                      'to '
                                                                                      'provide '
                                                                                      'a '
                                                                                      'password"\n'
                                                                                      'gpg '
                                                                                      '-c '
                                                                                      '/tmp/victim-files/victim-filex.zip\n'
                                                                                      '#<enter '
                                                                                      'passphrase '
                                                                                      'and '
                                                                                      'confirm>\n'
                                                                                      'ls '
                                                                                      '-l\n',
                                                                           'elevation_required': False,
                                                                           'name': 'sh',
                                                                           'prereq_command': 'which '
                                                                                             'gpg'},
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
    
