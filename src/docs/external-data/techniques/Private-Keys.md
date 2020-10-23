
# Private Keys

## Description

### MITRE Description

> Adversaries may search for private key certificate files on compromised systems for insecurely stored credentials. Private cryptographic keys and certificates are used for authentication, encryption/decryption, and digital signatures.(Citation: Wikipedia Public Key Crypto) Common key and certificate file extensions include: .key, .pgp, .gpg, .ppk., .p12, .pem, .pfx, .cer, .p7b, .asc. 

Adversaries may also look in common key directories, such as <code>~/.ssh</code> for SSH keys on * nix-based systems or <code>C:&#92;Users&#92;(username)&#92;.ssh&#92;</code> on Windows. These private keys can be used to authenticate to [Remote Services](https://attack.mitre.org/techniques/T1021) like SSH or for use in decrypting other collected files such as email.

Adversary tools have been discovered that search compromised systems for file extensions relating to cryptographic keys and certificates.(Citation: Kaspersky Careto)(Citation: Palo Alto Prince of Persia)

Some private keys require a password or passphrase for operation, so an adversary may also use [Input Capture](https://attack.mitre.org/techniques/T1056) for keylogging or attempt to [Brute Force](https://attack.mitre.org/techniques/T1110) the passphrase off-line.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1552/004

## Potential Commands

```
dir c:\ /b /s .key | findstr /e .key
find / -name id_rsa >> #{output_file}
find / -name id_dsa >> #{output_file}
mkdir #{output_folder}
find / -name id_rsa -exec rsync -R {} #{output_folder} \;
find / -name id_dsa -exec rsync -R {} #{output_folder} \;
mkdir #{output_folder}
find / -name id_rsa -exec cp --parents {} #{output_folder} \;
find / -name id_dsa -exec cp --parents {} #{output_folder} \;
mkdir /tmp/art-staging
find #{search_path} -name id_rsa -exec rsync -R {} /tmp/art-staging \;
find #{search_path} -name id_dsa -exec rsync -R {} /tmp/art-staging \;
find #{search_path} -name id_rsa >> /tmp/keyfile_locations.txt
find #{search_path} -name id_dsa >> /tmp/keyfile_locations.txt
mkdir /tmp/art-staging
find #{search_path} -name id_rsa -exec cp --parents {} /tmp/art-staging \;
find #{search_path} -name id_dsa -exec cp --parents {} /tmp/art-staging \;
```

## Commands Dataset

```
[{'command': 'dir c:\\ /b /s .key | findstr /e .key\n',
  'name': None,
  'source': 'atomics/T1552.004/T1552.004.yaml'},
 {'command': 'find / -name id_rsa >> #{output_file}\n'
             'find / -name id_dsa >> #{output_file}\n',
  'name': None,
  'source': 'atomics/T1552.004/T1552.004.yaml'},
 {'command': 'find #{search_path} -name id_rsa >> /tmp/keyfile_locations.txt\n'
             'find #{search_path} -name id_dsa >> /tmp/keyfile_locations.txt\n',
  'name': None,
  'source': 'atomics/T1552.004/T1552.004.yaml'},
 {'command': 'mkdir #{output_folder}\n'
             'find / -name id_rsa -exec cp --parents {} #{output_folder} \\;\n'
             'find / -name id_dsa -exec cp --parents {} #{output_folder} \\;\n',
  'name': None,
  'source': 'atomics/T1552.004/T1552.004.yaml'},
 {'command': 'mkdir /tmp/art-staging\n'
             'find #{search_path} -name id_rsa -exec cp --parents {} '
             '/tmp/art-staging \\;\n'
             'find #{search_path} -name id_dsa -exec cp --parents {} '
             '/tmp/art-staging \\;\n',
  'name': None,
  'source': 'atomics/T1552.004/T1552.004.yaml'},
 {'command': 'mkdir #{output_folder}\n'
             'find / -name id_rsa -exec rsync -R {} #{output_folder} \\;\n'
             'find / -name id_dsa -exec rsync -R {} #{output_folder} \\;\n',
  'name': None,
  'source': 'atomics/T1552.004/T1552.004.yaml'},
 {'command': 'mkdir /tmp/art-staging\n'
             'find #{search_path} -name id_rsa -exec rsync -R {} '
             '/tmp/art-staging \\;\n'
             'find #{search_path} -name id_dsa -exec rsync -R {} '
             '/tmp/art-staging \\;\n',
  'name': None,
  'source': 'atomics/T1552.004/T1552.004.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Unsecured Credentials: Private Keys': {'atomic_tests': [{'auto_generated_guid': '520ce462-7ca7-441e-b5a5-f8347f632696',
                                                                                   'description': 'Find '
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
                                                                                  {'auto_generated_guid': '46959285-906d-40fa-9437-5a439accd878',
                                                                                   'description': 'Discover '
                                                                                                  'private '
                                                                                                  'SSH '
                                                                                                  'keys '
                                                                                                  'on '
                                                                                                  'a '
                                                                                                  'macOS '
                                                                                                  'or '
                                                                                                  'Linux '
                                                                                                  'system.\n',
                                                                                   'executor': {'cleanup_command': 'rm '
                                                                                                                   '#{output_file}\n',
                                                                                                'command': 'find '
                                                                                                           '#{search_path} '
                                                                                                           '-name '
                                                                                                           'id_rsa '
                                                                                                           '>> '
                                                                                                           '#{output_file}\n'
                                                                                                           'find '
                                                                                                           '#{search_path} '
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
                                                                                                                       'type': 'path'},
                                                                                                       'search_path': {'default': '/',
                                                                                                                       'description': 'Path '
                                                                                                                                      'where '
                                                                                                                                      'to '
                                                                                                                                      'start '
                                                                                                                                      'searching '
                                                                                                                                      'from.',
                                                                                                                       'type': 'path'}},
                                                                                   'name': 'Discover '
                                                                                           'Private '
                                                                                           'SSH '
                                                                                           'Keys',
                                                                                   'supported_platforms': ['macos',
                                                                                                           'linux']},
                                                                                  {'auto_generated_guid': '7c247dc7-5128-4643-907b-73a76d9135c3',
                                                                                   'description': 'Copy '
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
                                                                                   'executor': {'cleanup_command': 'rm '
                                                                                                                   '#{output_folder}\n',
                                                                                                'command': 'mkdir '
                                                                                                           '#{output_folder}\n'
                                                                                                           'find '
                                                                                                           '#{search_path} '
                                                                                                           '-name '
                                                                                                           'id_rsa '
                                                                                                           '-exec '
                                                                                                           'cp '
                                                                                                           '--parents '
                                                                                                           '{} '
                                                                                                           '#{output_folder} '
                                                                                                           '\\;\n'
                                                                                                           'find '
                                                                                                           '#{search_path} '
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
                                                                                                                         'type': 'path'},
                                                                                                       'search_path': {'default': '/',
                                                                                                                       'description': 'Path '
                                                                                                                                      'where '
                                                                                                                                      'to '
                                                                                                                                      'start '
                                                                                                                                      'searching '
                                                                                                                                      'from.',
                                                                                                                       'type': 'path'}},
                                                                                   'name': 'Copy '
                                                                                           'Private '
                                                                                           'SSH '
                                                                                           'Keys '
                                                                                           'with '
                                                                                           'CP',
                                                                                   'supported_platforms': ['linux']},
                                                                                  {'auto_generated_guid': '864bb0b2-6bb5-489a-b43b-a77b3a16d68a',
                                                                                   'description': 'Copy '
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
                                                                                   'executor': {'cleanup_command': 'rm '
                                                                                                                   '-rf '
                                                                                                                   '#{output_folder}\n',
                                                                                                'command': 'mkdir '
                                                                                                           '#{output_folder}\n'
                                                                                                           'find '
                                                                                                           '#{search_path} '
                                                                                                           '-name '
                                                                                                           'id_rsa '
                                                                                                           '-exec '
                                                                                                           'rsync '
                                                                                                           '-R '
                                                                                                           '{} '
                                                                                                           '#{output_folder} '
                                                                                                           '\\;\n'
                                                                                                           'find '
                                                                                                           '#{search_path} '
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
                                                                                                                         'type': 'path'},
                                                                                                       'search_path': {'default': '/',
                                                                                                                       'description': 'Path '
                                                                                                                                      'where '
                                                                                                                                      'to '
                                                                                                                                      'start '
                                                                                                                                      'searching '
                                                                                                                                      'from.',
                                                                                                                       'type': 'path'}},
                                                                                   'name': 'Copy '
                                                                                           'Private '
                                                                                           'SSH '
                                                                                           'Keys '
                                                                                           'with '
                                                                                           'rsync',
                                                                                   'supported_platforms': ['macos',
                                                                                                           'linux']}],
                                                                 'attack_technique': 'T1552.004',
                                                                 'display_name': 'Unsecured '
                                                                                 'Credentials: '
                                                                                 'Private '
                                                                                 'Keys'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [Encrypt Sensitive Information](../mitigations/Encrypt-Sensitive-Information.md)

* [Audit](../mitigations/Audit.md)
    
* [Password Policies](../mitigations/Password-Policies.md)
    
* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)
    
* [Private Keys Mitigation](../mitigations/Private-Keys-Mitigation.md)
    

# Actors


* [Rocke](../actors/Rocke.md)

