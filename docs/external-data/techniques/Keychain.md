
# Keychain

## Description

### MITRE Description

> Keychains are the built-in way for macOS to keep track of users' passwords and credentials for many services and features such as WiFi passwords, websites, secure notes, certificates, and Kerberos. Keychain files are located in <code>~/Library/Keychains/</code>,<code>/Library/Keychains/</code>, and <code>/Network/Library/Keychains/</code>. (Citation: Wikipedia keychain) The <code>security</code> command-line utility, which is built into macOS by default, provides a useful way to manage these credentials.

To manage their credentials, users have to use additional credentials to access their keychain. If an adversary knows the credentials for the login keychain, then they can get access to all the other credentials stored in this vault. (Citation: External to DA, the OS X Way) By default, the passphrase for the keychain is the user’s logon credentials.

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['Administrator']
* Platforms: ['macOS']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1142

## Potential Commands

```
security -h
security find-certificate -a -p > allcerts.pem
security import /tmp/certs.pem -k

python/collection/osx/keychaindump
python/collection/osx/keychaindump
python/collection/osx/keychaindump_chainbreaker
python/collection/osx/keychaindump_chainbreaker
python/collection/osx/keychaindump_decrypt
python/collection/osx/keychaindump_decrypt
```

## Commands Dataset

```
[{'command': 'security -h\n'
             'security find-certificate -a -p > allcerts.pem\n'
             'security import /tmp/certs.pem -k\n',
  'name': None,
  'source': 'atomics/T1142/T1142.yaml'},
 {'command': 'python/collection/osx/keychaindump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/keychaindump',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/keychaindump_chainbreaker',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/keychaindump_chainbreaker',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/keychaindump_decrypt',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/keychaindump_decrypt',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Keychain': {'atomic_tests': [{'description': '### '
                                                                       'Keychain '
                                                                       'Files\n'
                                                                       '\n'
                                                                       '  '
                                                                       '~/Library/Keychains/\n'
                                                                       '\n'
                                                                       '  '
                                                                       '/Library/Keychains/\n'
                                                                       '\n'
                                                                       '  '
                                                                       '/Network/Library/Keychains/\n'
                                                                       '\n'
                                                                       '  '
                                                                       '[Security '
                                                                       'Reference](https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man1/security.1.html)\n'
                                                                       '\n'
                                                                       '  '
                                                                       '[Keychain '
                                                                       'dumper](https://github.com/juuso/keychaindump)\n',
                                                        'executor': {'command': 'security '
                                                                                '-h\n'
                                                                                'security '
                                                                                'find-certificate '
                                                                                '-a '
                                                                                '-p '
                                                                                '> '
                                                                                'allcerts.pem\n'
                                                                                'security '
                                                                                'import '
                                                                                '/tmp/certs.pem '
                                                                                '-k\n',
                                                                     'name': 'sh'},
                                                        'name': 'Keychain',
                                                        'supported_platforms': ['macos']}],
                                      'attack_technique': 'T1142',
                                      'display_name': 'Keychain'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1142',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/osx/keychaindump":  '
                                                                                 '["T1142"],',
                                            'Empire Module': 'python/collection/osx/keychaindump',
                                            'Technique': 'Keychain'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1142',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/osx/keychaindump_chainbreaker":  '
                                                                                 '["T1142"],',
                                            'Empire Module': 'python/collection/osx/keychaindump_chainbreaker',
                                            'Technique': 'Keychain'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1142',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/osx/keychaindump_decrypt":  '
                                                                                 '["T1142"],',
                                            'Empire Module': 'python/collection/osx/keychaindump_decrypt',
                                            'Technique': 'Keychain'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations

None

# Actors

None
