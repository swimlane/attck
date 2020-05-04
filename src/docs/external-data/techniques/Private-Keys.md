
# Private Keys

## Description

### MITRE Description

> Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures. (Citation: Wikipedia Public Key Crypto)

Adversaries may gather private keys from compromised systems for use in authenticating to [Remote Services](https://attack.mitre.org/techniques/T1021) like SSH or for use in decrypting other collected files such as email. Common key and certificate file extensions include: .key, .pgp, .gpg, .ppk., .p12, .pem, .pfx, .cer, .p7b, .asc. Adversaries may also look in common key directories, such as <code>~/.ssh</code> for SSH keys on * nix-based systems or <code>C:\Users\(username)\.ssh\</code> on Windows.

Private keys should require a password or passphrase for operation, so an adversary may also use [Input Capture](https://attack.mitre.org/techniques/T1056) for keylogging or attempt to [Brute Force](https://attack.mitre.org/techniques/T1110) the passphrase off-line.

Adversary tools have been discovered that search compromised systems for file extensions relating to cryptographic keys and certificates. (Citation: Kaspersky Careto) (Citation: Palo Alto Prince of Persia)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1145

## Potential Commands

```
dir c:\ /b /s .key | findstr /e .key

find / -name id_rsa >> /tmp/keyfile_locations.txt
find / -name id_dsa >> /tmp/keyfile_locations.txt

mkdir /tmp/art-staging
find / -name id_rsa -exec cp --parents {} /tmp/art-staging \;
find / -name id_dsa -exec cp --parents {} /tmp/art-staging \;

mkdir /tmp/art-staging
find / -name id_rsa -exec rsync -R {} /tmp/art-staging \;
find / -name id_dsa -exec rsync -R {} /tmp/art-staging \;

{'windows': {'psh': {'command': 'foreach($i in @(".key",".pgp",".gpg",".ppk",".p12",".pem",".pfx",".cer",".p7b",".asc",".crt")){Get-ChildItem -Path c:\\ -Depth 3 -File -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.name -Match "$i$"}}\n'}, 'cmd': {'command': 'for %i in (\\.key \\.pgp \\.gpg \\.ppk \\.p12 \\.pem \\.pfx \\.cer \\.p7b \\.asc) do (dir c:\\ /b /s .key | findstr /e "%i")\n'}}, 'darwin': {'sh': {'command': 'for i in .key .pgp .gpg .ppk .p12 .pem .pfx .cer .p7b .asc .crt;do find /Users -maxdepth 3 -name "*${i}" 2>/dev/null;done;\n'}}, 'linux': {'sh': {'command': 'for i in .key .pgp .gpg .ppk .p12 .pem .pfx .cer .p7b .asc .crt;do find /etc -maxdepth 3 -name "*${i}" 2>/dev/null;done;'}}}
powershell/credentials/mimikatz/certs
powershell/credentials/mimikatz/certs
powershell/credentials/mimikatz/keys
powershell/credentials/mimikatz/keys
```

## Commands Dataset

```
[{'command': 'dir c:\\ /b /s .key | findstr /e .key\n',
  'name': None,
  'source': 'atomics/T1145/T1145.yaml'},
 {'command': 'find / -name id_rsa >> /tmp/keyfile_locations.txt\n'
             'find / -name id_dsa >> /tmp/keyfile_locations.txt\n',
  'name': None,
  'source': 'atomics/T1145/T1145.yaml'},
 {'command': 'mkdir /tmp/art-staging\n'
             'find / -name id_rsa -exec cp --parents {} /tmp/art-staging \\;\n'
             'find / -name id_dsa -exec cp --parents {} /tmp/art-staging \\;\n',
  'name': None,
  'source': 'atomics/T1145/T1145.yaml'},
 {'command': 'mkdir /tmp/art-staging\n'
             'find / -name id_rsa -exec rsync -R {} /tmp/art-staging \\;\n'
             'find / -name id_dsa -exec rsync -R {} /tmp/art-staging \\;\n',
  'name': None,
  'source': 'atomics/T1145/T1145.yaml'},
 {'command': {'darwin': {'sh': {'command': 'for i in .key .pgp .gpg .ppk .p12 '
                                           '.pem .pfx .cer .p7b .asc .crt;do '
                                           'find /Users -maxdepth 3 -name '
                                           '"*${i}" 2>/dev/null;done;\n'}},
              'linux': {'sh': {'command': 'for i in .key .pgp .gpg .ppk .p12 '
                                          '.pem .pfx .cer .p7b .asc .crt;do '
                                          'find /etc -maxdepth 3 -name "*${i}" '
                                          '2>/dev/null;done;'}},
              'windows': {'cmd': {'command': 'for %i in (\\.key \\.pgp \\.gpg '
                                             '\\.ppk \\.p12 \\.pem \\.pfx '
                                             '\\.cer \\.p7b \\.asc) do (dir '
                                             'c:\\ /b /s .key | findstr /e '
                                             '"%i")\n'},
                          'psh': {'command': 'foreach($i in '
                                             '@(".key",".pgp",".gpg",".ppk",".p12",".pem",".pfx",".cer",".p7b",".asc",".crt")){Get-ChildItem '
                                             '-Path c:\\ -Depth 3 -File '
                                             '-Recurse -ErrorAction '
                                             'SilentlyContinue | Where-Object '
                                             '{$_.name -Match "$i$"}}\n'}}},
  'name': 'Find private keys on the file system',
  'source': 'data/abilities/credential-access/de632c2d-a729-4b77-b781-6a6b09c148ba.yml'},
 {'command': 'powershell/credentials/mimikatz/certs',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/certs',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/keys',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/mimikatz/keys',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: the attacker to find the private key file under linux\n'
           'description: Ubuntu18.04\n'
           'references: '
           'https://github.com/12306Bro/Threathunting/blob/master/T1145-linux- '
           'private .md\n'
           'tags: T1145\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: linux\n'
           '\xa0\xa0\xa0\xa0service: history\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0keywords:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0- sudo find / -name * .pgp\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0- sudo find / -name * .pem\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0- sudo find / -name * .ppk\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0- sudo find / -name * .p12\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0- sudo find / -name * .key\n'
           '\xa0\xa0\xa0\xa0condition: keywords\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Private Keys': {'atomic_tests': [{'description': 'Find '
                                                                           'private '
                                                                           'keys '
                                                                           'on '
                                                                           'the '
                                                                           'Windows '
                                                                           'file '
                                                                           'system.\n'
                                                                           'File '
                                                                           'extensions '
                                                                           'include: '
                                                                           '.key, '
                                                                           '.pgp, '
                                                                           '.gpg, '
                                                                           '.ppk., '
                                                                           '.p12, '
                                                                           '.pem, '
                                                                           'pfx, '
                                                                           '.cer, '
                                                                           '.p7b, '
                                                                           '.asc\n',
                                                            'executor': {'command': 'dir '
                                                                                    'c:\\ '
                                                                                    '/b '
                                                                                    '/s '
                                                                                    '.key '
                                                                                    '| '
                                                                                    'findstr '
                                                                                    '/e '
                                                                                    '.key\n',
                                                                         'elevation_required': True,
                                                                         'name': 'command_prompt'},
                                                            'name': 'Private '
                                                                    'Keys',
                                                            'supported_platforms': ['windows']},
                                                           {'description': 'Discover '
                                                                           'private '
                                                                           'SSH '
                                                                           'keys '
                                                                           'on '
                                                                           'a '
                                                                           'macOS '
                                                                           'or '
                                                                           'Linux '
                                                                           'system.\n',
                                                            'executor': {'command': 'find '
                                                                                    '/ '
                                                                                    '-name '
                                                                                    'id_rsa '
                                                                                    '>> '
                                                                                    '#{output_file}\n'
                                                                                    'find '
                                                                                    '/ '
                                                                                    '-name '
                                                                                    'id_dsa '
                                                                                    '>> '
                                                                                    '#{output_file}\n',
                                                                         'name': 'sh'},
                                                            'input_arguments': {'output_file': {'default': '/tmp/keyfile_locations.txt',
                                                                                                'description': 'Output '
                                                                                                               'file '
                                                                                                               'containing '
                                                                                                               'locations '
                                                                                                               'of '
                                                                                                               'SSH '
                                                                                                               'key '
                                                                                                               'files',
                                                                                                'type': 'path'}},
                                                            'name': 'Discover '
                                                                    'Private '
                                                                    'SSH Keys',
                                                            'supported_platforms': ['macos',
                                                                                    'linux']},
                                                           {'description': 'Copy '
                                                                           'private '
                                                                           'SSH '
                                                                           'keys '
                                                                           'on '
                                                                           'a '
                                                                           'Linux '
                                                                           'system '
                                                                           'to '
                                                                           'a '
                                                                           'staging '
                                                                           'folder '
                                                                           'using '
                                                                           'the '
                                                                           '`cp` '
                                                                           'command.\n',
                                                            'executor': {'command': 'mkdir '
                                                                                    '#{output_folder}\n'
                                                                                    'find '
                                                                                    '/ '
                                                                                    '-name '
                                                                                    'id_rsa '
                                                                                    '-exec '
                                                                                    'cp '
                                                                                    '--parents '
                                                                                    '{} '
                                                                                    '#{output_folder} '
                                                                                    '\\;\n'
                                                                                    'find '
                                                                                    '/ '
                                                                                    '-name '
                                                                                    'id_dsa '
                                                                                    '-exec '
                                                                                    'cp '
                                                                                    '--parents '
                                                                                    '{} '
                                                                                    '#{output_folder} '
                                                                                    '\\;\n',
                                                                         'name': 'sh'},
                                                            'input_arguments': {'output_folder': {'default': '/tmp/art-staging',
                                                                                                  'description': 'Output '
                                                                                                                 'folder '
                                                                                                                 'containing '
                                                                                                                 'copies '
                                                                                                                 'of '
                                                                                                                 'SSH '
                                                                                                                 'private '
                                                                                                                 'key '
                                                                                                                 'files',
                                                                                                  'type': 'path'}},
                                                            'name': 'Copy '
                                                                    'Private '
                                                                    'SSH Keys '
                                                                    'with CP',
                                                            'supported_platforms': ['linux']},
                                                           {'description': 'Copy '
                                                                           'private '
                                                                           'SSH '
                                                                           'keys '
                                                                           'on '
                                                                           'a '
                                                                           'Linux '
                                                                           'or '
                                                                           'macOS '
                                                                           'system '
                                                                           'to '
                                                                           'a '
                                                                           'staging '
                                                                           'folder '
                                                                           'using '
                                                                           'the '
                                                                           '`rsync` '
                                                                           'command.\n',
                                                            'executor': {'command': 'mkdir '
                                                                                    '#{output_folder}\n'
                                                                                    'find '
                                                                                    '/ '
                                                                                    '-name '
                                                                                    'id_rsa '
                                                                                    '-exec '
                                                                                    'rsync '
                                                                                    '-R '
                                                                                    '{} '
                                                                                    '#{output_folder} '
                                                                                    '\\;\n'
                                                                                    'find '
                                                                                    '/ '
                                                                                    '-name '
                                                                                    'id_dsa '
                                                                                    '-exec '
                                                                                    'rsync '
                                                                                    '-R '
                                                                                    '{} '
                                                                                    '#{output_folder} '
                                                                                    '\\;\n',
                                                                         'name': 'sh'},
                                                            'input_arguments': {'output_folder': {'default': '/tmp/art-staging',
                                                                                                  'description': 'Output '
                                                                                                                 'folder '
                                                                                                                 'containing '
                                                                                                                 'copies '
                                                                                                                 'of '
                                                                                                                 'SSH '
                                                                                                                 'private '
                                                                                                                 'key '
                                                                                                                 'files',
                                                                                                  'type': 'path'}},
                                                            'name': 'Copy '
                                                                    'Private '
                                                                    'SSH Keys '
                                                                    'with '
                                                                    'rsync',
                                                            'supported_platforms': ['macos',
                                                                                    'linux']}],
                                          'attack_technique': 'T1145',
                                          'display_name': 'Private Keys'}},
 {'Mitre Stockpile - Find private keys on the file system': {'description': 'Find '
                                                                            'private '
                                                                            'keys '
                                                                            'on '
                                                                            'the '
                                                                            'file '
                                                                            'system',
                                                             'id': 'de632c2d-a729-4b77-b781-6a6b09c148ba',
                                                             'name': 'Find '
                                                                     'private '
                                                                     'keys',
                                                             'platforms': {'darwin': {'sh': {'command': 'for '
                                                                                                        'i '
                                                                                                        'in '
                                                                                                        '.key '
                                                                                                        '.pgp '
                                                                                                        '.gpg '
                                                                                                        '.ppk '
                                                                                                        '.p12 '
                                                                                                        '.pem '
                                                                                                        '.pfx '
                                                                                                        '.cer '
                                                                                                        '.p7b '
                                                                                                        '.asc '
                                                                                                        '.crt;do '
                                                                                                        'find '
                                                                                                        '/Users '
                                                                                                        '-maxdepth '
                                                                                                        '3 '
                                                                                                        '-name '
                                                                                                        '"*${i}" '
                                                                                                        '2>/dev/null;done;\n'}},
                                                                           'linux': {'sh': {'command': 'for '
                                                                                                       'i '
                                                                                                       'in '
                                                                                                       '.key '
                                                                                                       '.pgp '
                                                                                                       '.gpg '
                                                                                                       '.ppk '
                                                                                                       '.p12 '
                                                                                                       '.pem '
                                                                                                       '.pfx '
                                                                                                       '.cer '
                                                                                                       '.p7b '
                                                                                                       '.asc '
                                                                                                       '.crt;do '
                                                                                                       'find '
                                                                                                       '/etc '
                                                                                                       '-maxdepth '
                                                                                                       '3 '
                                                                                                       '-name '
                                                                                                       '"*${i}" '
                                                                                                       '2>/dev/null;done;'}},
                                                                           'windows': {'cmd': {'command': 'for '
                                                                                                          '%i '
                                                                                                          'in '
                                                                                                          '(\\.key '
                                                                                                          '\\.pgp '
                                                                                                          '\\.gpg '
                                                                                                          '\\.ppk '
                                                                                                          '\\.p12 '
                                                                                                          '\\.pem '
                                                                                                          '\\.pfx '
                                                                                                          '\\.cer '
                                                                                                          '\\.p7b '
                                                                                                          '\\.asc) '
                                                                                                          'do '
                                                                                                          '(dir '
                                                                                                          'c:\\ '
                                                                                                          '/b '
                                                                                                          '/s '
                                                                                                          '.key '
                                                                                                          '| '
                                                                                                          'findstr '
                                                                                                          '/e '
                                                                                                          '"%i")\n'},
                                                                                       'psh': {'command': 'foreach($i '
                                                                                                          'in '
                                                                                                          '@(".key",".pgp",".gpg",".ppk",".p12",".pem",".pfx",".cer",".p7b",".asc",".crt")){Get-ChildItem '
                                                                                                          '-Path '
                                                                                                          'c:\\ '
                                                                                                          '-Depth '
                                                                                                          '3 '
                                                                                                          '-File '
                                                                                                          '-Recurse '
                                                                                                          '-ErrorAction '
                                                                                                          'SilentlyContinue '
                                                                                                          '| '
                                                                                                          'Where-Object '
                                                                                                          '{$_.name '
                                                                                                          '-Match '
                                                                                                          '"$i$"}}\n'}}},
                                                             'tactic': 'credential-access',
                                                             'technique': {'attack_id': 'T1145',
                                                                           'name': 'Private '
                                                                                   'Keys'}}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1145',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/mimikatz/certs":  '
                                                                                 '["T1145"],',
                                            'Empire Module': 'powershell/credentials/mimikatz/certs',
                                            'Technique': 'Private Keys'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1145',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/mimikatz/keys":  '
                                                                                 '["T1145"],',
                                            'Empire Module': 'powershell/credentials/mimikatz/keys',
                                            'Technique': 'Private Keys'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations

None

# Actors

None
