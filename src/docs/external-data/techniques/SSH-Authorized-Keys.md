
# SSH Authorized Keys

## Description

### MITRE Description

> Adversaries may modify the SSH <code>authorized_keys</code> file to maintain persistence on a victim host. Linux distributions and macOS commonly use key-based authentication to secure the authentication process of SSH sessions for remote management. The <code>authorized_keys</code> file in SSH specifies the SSH keys that can be used for logging into the user account for which the file is configured. This file is usually found in the user's home directory under <code>&lt;user-home&gt;/.ssh/authorized_keys</code>.(Citation: SSH Authorized Keys) Users may edit the system’s SSH config file to modify the directives PubkeyAuthentication and RSAAuthentication to the value “yes” to ensure public key and RSA authentication are enabled. The SSH config file is usually located under <code>/etc/ssh/sshd_config</code>.

Adversaries may modify SSH <code>authorized_keys</code> files directly with scripts or shell commands to add their own adversary-supplied public keys. This ensures that an adversary possessing the corresponding private key may log in as an existing user via SSH.(Citation: Venafi SSH Key Abuse) (Citation: Cybereason Linux Exim Worm)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator']
* Platforms: ['Linux', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1098/004

## Potential Commands

```
if [ -f ~/.ssh/authorized_keys ]; then ssh_authorized_keys=$(cat ~/.ssh/authorized_keys); echo $ssh_authorized_keys > ~/.ssh/authorized_keys; fi;
```

## Commands Dataset

```
[{'command': 'if [ -f ~/.ssh/authorized_keys ]; then ssh_authorized_keys=$(cat '
             '~/.ssh/authorized_keys); echo $ssh_authorized_keys > '
             '~/.ssh/authorized_keys; fi;\n',
  'name': None,
  'source': 'atomics/T1098.004/T1098.004.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - SSH Authorized Keys': {'atomic_tests': [{'auto_generated_guid': '342cc723-127c-4d3a-8292-9c0c6b4ecadc',
                                                                   'description': 'Modify '
                                                                                  'contents '
                                                                                  'of '
                                                                                  '<user-home>/.ssh/authorized_keys '
                                                                                  'to '
                                                                                  'maintain '
                                                                                  'persistence '
                                                                                  'on '
                                                                                  'victim '
                                                                                  'host. \n'
                                                                                  'If '
                                                                                  'the '
                                                                                  'user '
                                                                                  'is '
                                                                                  'able '
                                                                                  'to '
                                                                                  'save '
                                                                                  'the '
                                                                                  'same '
                                                                                  'contents '
                                                                                  'in '
                                                                                  'the '
                                                                                  'authorized_keys '
                                                                                  'file, '
                                                                                  'it '
                                                                                  'shows '
                                                                                  'user '
                                                                                  'can '
                                                                                  'modify '
                                                                                  'the '
                                                                                  'file.\n',
                                                                   'executor': {'cleanup_command': 'unset '
                                                                                                   'ssh_authorized_keys\n',
                                                                                'command': 'if '
                                                                                           '[ '
                                                                                           '-f '
                                                                                           '~/.ssh/authorized_keys '
                                                                                           ']; '
                                                                                           'then '
                                                                                           'ssh_authorized_keys=$(cat '
                                                                                           '~/.ssh/authorized_keys); '
                                                                                           'echo '
                                                                                           '$ssh_authorized_keys '
                                                                                           '> '
                                                                                           '~/.ssh/authorized_keys; '
                                                                                           'fi;\n',
                                                                                'elevation_required': False,
                                                                                'name': 'bash'},
                                                                   'name': 'Modify '
                                                                           'SSH '
                                                                           'Authorized '
                                                                           'Keys',
                                                                   'supported_platforms': ['macos',
                                                                                           'linux']}],
                                                 'attack_technique': 'T1098.004',
                                                 'display_name': 'SSH '
                                                                 'Authorized '
                                                                 'Keys'}}]
```

# Tactics


* [Persistence](../tactics/Persistence.md)


# Mitigations


* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)

* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    

# Actors

None
