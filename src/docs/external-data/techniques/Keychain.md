
# Keychain

## Description

### MITRE Description

> Adversaries may collect the keychain storage data from a system to acquire credentials. Keychains are the built-in way for macOS to keep track of users' passwords and credentials for many services and features such as WiFi passwords, websites, secure notes, certificates, and Kerberos. Keychain files are located in <code>~/Library/Keychains/</code>,<code>/Library/Keychains/</code>, and <code>/Network/Library/Keychains/</code>. (Citation: Wikipedia keychain) The <code>security</code> command-line utility, which is built into macOS by default, provides a useful way to manage these credentials.

To manage their credentials, users have to use additional credentials to access their keychain. If an adversary knows the credentials for the login keychain, then they can get access to all the other credentials stored in this vault. (Citation: External to DA, the OS X Way) By default, the passphrase for the keychain is the user’s logon credentials.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator']
* Platforms: ['macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1555/001

## Potential Commands

```
security -h
security find-certificate -a -p > /tmp/certs.pem
security import /tmp/certs.pem -k
```

## Commands Dataset

```
[{'command': 'security -h\n'
             'security find-certificate -a -p > /tmp/certs.pem\n'
             'security import /tmp/certs.pem -k\n',
  'name': None,
  'source': 'atomics/T1555.001/T1555.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Credentials from Password Stores: Keychain': {'atomic_tests': [{'auto_generated_guid': '1864fdec-ff86-4452-8c30-f12507582a93',
                                                                                          'description': '### '
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
                                                                                                                  '#{cert_export}\n'
                                                                                                                  'security '
                                                                                                                  'import '
                                                                                                                  '#{cert_export} '
                                                                                                                  '-k\n',
                                                                                                       'name': 'sh'},
                                                                                          'input_arguments': {'cert_export': {'default': '/tmp/certs.pem',
                                                                                                                              'description': 'Specify '
                                                                                                                                             'the '
                                                                                                                                             'path '
                                                                                                                                             'of '
                                                                                                                                             'the '
                                                                                                                                             'certificates '
                                                                                                                                             'to '
                                                                                                                                             'export.',
                                                                                                                              'type': 'path'}},
                                                                                          'name': 'Keychain',
                                                                                          'supported_platforms': ['macos']}],
                                                                        'attack_technique': 'T1555.001',
                                                                        'display_name': 'Credentials '
                                                                                        'from '
                                                                                        'Password '
                                                                                        'Stores: '
                                                                                        'Keychain'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [Password Policies](../mitigations/Password-Policies.md)


# Actors

None
