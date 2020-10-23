
# Web Protocols

## Description

### MITRE Description

> Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. 

Protocols such as HTTP and HTTPS that carry web traffic may be very common in environments. HTTP/S packets have many fields and headers in which data can be concealed. An adversary may abuse these protocols to communicate with systems under their control within a victim network while also mimicking normal, expected traffic. 

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1071/001

## Potential Commands

```
Invoke-WebRequest www.google.com -UserAgent "HttpBrowser/1.0" | out-null
Invoke-WebRequest www.google.com -UserAgent "Wget/1.9+cvs-stable (Red Hat modified)" | out-null
Invoke-WebRequest www.google.com -UserAgent "Opera/8.81 (Windows NT 6.0; U; en)" | out-null
Invoke-WebRequest www.google.com -UserAgent "*<|>*" | out-null
curl -s -A "HttpBrowser/1.0" -m3 www.google.com
curl -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 www.google.com
curl -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 www.google.com
curl -s -A "*<|>*" -m3 www.google.com
C:\Windows\System32\Curl.exe -s -A "HttpBrowser/1.0" -m3 #{domain} >nul 2>&1
C:\Windows\System32\Curl.exe -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 #{domain} >nul 2>&1
C:\Windows\System32\Curl.exe -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 #{domain} >nul 2>&1
C:\Windows\System32\Curl.exe -s -A "*<|>*" -m3 #{domain} >nul 2>&1
#{curl_path} -s -A "HttpBrowser/1.0" -m3 www.google.com >nul 2>&1
#{curl_path} -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 www.google.com >nul 2>&1
#{curl_path} -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 www.google.com >nul 2>&1
#{curl_path} -s -A "*<|>*" -m3 www.google.com >nul 2>&1
```

## Commands Dataset

```
[{'command': 'Invoke-WebRequest www.google.com -UserAgent "HttpBrowser/1.0" | '
             'out-null\n'
             'Invoke-WebRequest www.google.com -UserAgent "Wget/1.9+cvs-stable '
             '(Red Hat modified)" | out-null\n'
             'Invoke-WebRequest www.google.com -UserAgent "Opera/8.81 (Windows '
             'NT 6.0; U; en)" | out-null\n'
             'Invoke-WebRequest www.google.com -UserAgent "*<|>*" | out-null\n',
  'name': None,
  'source': 'atomics/T1071.001/T1071.001.yaml'},
 {'command': '#{curl_path} -s -A "HttpBrowser/1.0" -m3 www.google.com >nul '
             '2>&1\n'
             '#{curl_path} -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 '
             'www.google.com >nul 2>&1\n'
             '#{curl_path} -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 '
             'www.google.com >nul 2>&1\n'
             '#{curl_path} -s -A "*<|>*" -m3 www.google.com >nul 2>&1\n',
  'name': None,
  'source': 'atomics/T1071.001/T1071.001.yaml'},
 {'command': 'C:\\Windows\\System32\\Curl.exe -s -A "HttpBrowser/1.0" -m3 '
             '#{domain} >nul 2>&1\n'
             'C:\\Windows\\System32\\Curl.exe -s -A "Wget/1.9+cvs-stable (Red '
             'Hat modified)" -m3 #{domain} >nul 2>&1\n'
             'C:\\Windows\\System32\\Curl.exe -s -A "Opera/8.81 (Windows NT '
             '6.0; U; en)" -m3 #{domain} >nul 2>&1\n'
             'C:\\Windows\\System32\\Curl.exe -s -A "*<|>*" -m3 #{domain} >nul '
             '2>&1\n',
  'name': None,
  'source': 'atomics/T1071.001/T1071.001.yaml'},
 {'command': 'curl -s -A "HttpBrowser/1.0" -m3 www.google.com\n'
             'curl -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 '
             'www.google.com\n'
             'curl -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 '
             'www.google.com\n'
             'curl -s -A "*<|>*" -m3 www.google.com\n',
  'name': None,
  'source': 'atomics/T1071.001/T1071.001.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Application Layer Protocol: Web Protocols': {'atomic_tests': [{'auto_generated_guid': '81c13829-f6c9-45b8-85a6-053366d55297',
                                                                                         'description': 'This '
                                                                                                        'test '
                                                                                                        'simulates '
                                                                                                        'an '
                                                                                                        'infected '
                                                                                                        'host '
                                                                                                        'beaconing '
                                                                                                        'to '
                                                                                                        'command '
                                                                                                        'and '
                                                                                                        'control. '
                                                                                                        'Upon '
                                                                                                        'execution, '
                                                                                                        'no '
                                                                                                        'output '
                                                                                                        'will '
                                                                                                        'be '
                                                                                                        'displayed. \n'
                                                                                                        'Use '
                                                                                                        'an '
                                                                                                        'application '
                                                                                                        'such '
                                                                                                        'as '
                                                                                                        'Wireshark '
                                                                                                        'to '
                                                                                                        'record '
                                                                                                        'the '
                                                                                                        'session '
                                                                                                        'and '
                                                                                                        'observe '
                                                                                                        'user '
                                                                                                        'agent '
                                                                                                        'strings '
                                                                                                        'and '
                                                                                                        'responses.\n'
                                                                                                        '\n'
                                                                                                        'Inspired '
                                                                                                        'by '
                                                                                                        'APTSimulator '
                                                                                                        '- '
                                                                                                        'https://github.com/NextronSystems/APTSimulator/blob/master/test-sets/command-and-control/malicious-user-agents.bat\n',
                                                                                         'executor': {'command': 'Invoke-WebRequest '
                                                                                                                 '#{domain} '
                                                                                                                 '-UserAgent '
                                                                                                                 '"HttpBrowser/1.0" '
                                                                                                                 '| '
                                                                                                                 'out-null\n'
                                                                                                                 'Invoke-WebRequest '
                                                                                                                 '#{domain} '
                                                                                                                 '-UserAgent '
                                                                                                                 '"Wget/1.9+cvs-stable '
                                                                                                                 '(Red '
                                                                                                                 'Hat '
                                                                                                                 'modified)" '
                                                                                                                 '| '
                                                                                                                 'out-null\n'
                                                                                                                 'Invoke-WebRequest '
                                                                                                                 '#{domain} '
                                                                                                                 '-UserAgent '
                                                                                                                 '"Opera/8.81 '
                                                                                                                 '(Windows '
                                                                                                                 'NT '
                                                                                                                 '6.0; '
                                                                                                                 'U; '
                                                                                                                 'en)" '
                                                                                                                 '| '
                                                                                                                 'out-null\n'
                                                                                                                 'Invoke-WebRequest '
                                                                                                                 '#{domain} '
                                                                                                                 '-UserAgent '
                                                                                                                 '"*<|>*" '
                                                                                                                 '| '
                                                                                                                 'out-null\n',
                                                                                                      'name': 'powershell'},
                                                                                         'input_arguments': {'domain': {'default': 'www.google.com',
                                                                                                                        'description': 'Default '
                                                                                                                                       'domain '
                                                                                                                                       'to '
                                                                                                                                       'simulate '
                                                                                                                                       'against',
                                                                                                                        'type': 'string'}},
                                                                                         'name': 'Malicious '
                                                                                                 'User '
                                                                                                 'Agents '
                                                                                                 '- '
                                                                                                 'Powershell',
                                                                                         'supported_platforms': ['windows']},
                                                                                        {'auto_generated_guid': 'dc3488b0-08c7-4fea-b585-905c83b48180',
                                                                                         'dependencies': [{'description': 'Curl '
                                                                                                                          'must '
                                                                                                                          'be '
                                                                                                                          'installed '
                                                                                                                          'on '
                                                                                                                          'system \n',
                                                                                                           'get_prereq_command': 'Invoke-WebRequest '
                                                                                                                                 '"https://curl.haxx.se/windows/dl-7.71.1/curl-7.71.1-win32-mingw.zip" '
                                                                                                                                 '-Outfile '
                                                                                                                                 '$env:temp\\curl.zip\n'
                                                                                                                                 'Expand-Archive '
                                                                                                                                 '-Path '
                                                                                                                                 '$env:temp\\curl.zip '
                                                                                                                                 '-DestinationPath '
                                                                                                                                 '$env:temp\\curl\n'
                                                                                                                                 'Copy-Item '
                                                                                                                                 '$env:temp\\curl\\curl-7.71.1-win32-mingw\\bin\\curl.exe '
                                                                                                                                 '#{curl_path}\n'
                                                                                                                                 'Remove-Item '
                                                                                                                                 '$env:temp\\curl\n'
                                                                                                                                 'Remove-Item '
                                                                                                                                 '$env:temp\\curl.zip\n',
                                                                                                           'prereq_command': 'if '
                                                                                                                             '(Test-Path '
                                                                                                                             '#{curl_path}) '
                                                                                                                             '{exit '
                                                                                                                             '0} '
                                                                                                                             'else '
                                                                                                                             '{exit '
                                                                                                                             '1}\n'}],
                                                                                         'dependency_executor_name': 'powershell',
                                                                                         'description': 'This '
                                                                                                        'test '
                                                                                                        'simulates '
                                                                                                        'an '
                                                                                                        'infected '
                                                                                                        'host '
                                                                                                        'beaconing '
                                                                                                        'to '
                                                                                                        'command '
                                                                                                        'and '
                                                                                                        'control. '
                                                                                                        'Upon '
                                                                                                        'execution, '
                                                                                                        'no '
                                                                                                        'out '
                                                                                                        'put '
                                                                                                        'will '
                                                                                                        'be '
                                                                                                        'displayed. \n'
                                                                                                        'Use '
                                                                                                        'an '
                                                                                                        'application '
                                                                                                        'such '
                                                                                                        'as '
                                                                                                        'Wireshark '
                                                                                                        'to '
                                                                                                        'record '
                                                                                                        'the '
                                                                                                        'session '
                                                                                                        'and '
                                                                                                        'observe '
                                                                                                        'user '
                                                                                                        'agent '
                                                                                                        'strings '
                                                                                                        'and '
                                                                                                        'responses.\n'
                                                                                                        '\n'
                                                                                                        'Inspired '
                                                                                                        'by '
                                                                                                        'APTSimulator '
                                                                                                        '- '
                                                                                                        'https://github.com/NextronSystems/APTSimulator/blob/master/test-sets/command-and-control/malicious-user-agents.bat\n',
                                                                                         'executor': {'command': '#{curl_path} '
                                                                                                                 '-s '
                                                                                                                 '-A '
                                                                                                                 '"HttpBrowser/1.0" '
                                                                                                                 '-m3 '
                                                                                                                 '#{domain} '
                                                                                                                 '>nul '
                                                                                                                 '2>&1\n'
                                                                                                                 '#{curl_path} '
                                                                                                                 '-s '
                                                                                                                 '-A '
                                                                                                                 '"Wget/1.9+cvs-stable '
                                                                                                                 '(Red '
                                                                                                                 'Hat '
                                                                                                                 'modified)" '
                                                                                                                 '-m3 '
                                                                                                                 '#{domain} '
                                                                                                                 '>nul '
                                                                                                                 '2>&1\n'
                                                                                                                 '#{curl_path} '
                                                                                                                 '-s '
                                                                                                                 '-A '
                                                                                                                 '"Opera/8.81 '
                                                                                                                 '(Windows '
                                                                                                                 'NT '
                                                                                                                 '6.0; '
                                                                                                                 'U; '
                                                                                                                 'en)" '
                                                                                                                 '-m3 '
                                                                                                                 '#{domain} '
                                                                                                                 '>nul '
                                                                                                                 '2>&1\n'
                                                                                                                 '#{curl_path} '
                                                                                                                 '-s '
                                                                                                                 '-A '
                                                                                                                 '"*<|>*" '
                                                                                                                 '-m3 '
                                                                                                                 '#{domain} '
                                                                                                                 '>nul '
                                                                                                                 '2>&1\n',
                                                                                                      'name': 'command_prompt'},
                                                                                         'input_arguments': {'curl_path': {'default': 'C:\\Windows\\System32\\Curl.exe',
                                                                                                                           'description': 'path '
                                                                                                                                          'to '
                                                                                                                                          'curl.exe',
                                                                                                                           'type': 'path'},
                                                                                                             'domain': {'default': 'www.google.com',
                                                                                                                        'description': 'Default '
                                                                                                                                       'domain '
                                                                                                                                       'to '
                                                                                                                                       'simulate '
                                                                                                                                       'against',
                                                                                                                        'type': 'string'}},
                                                                                         'name': 'Malicious '
                                                                                                 'User '
                                                                                                 'Agents '
                                                                                                 '- '
                                                                                                 'CMD',
                                                                                         'supported_platforms': ['windows']},
                                                                                        {'auto_generated_guid': '2d7c471a-e887-4b78-b0dc-b0df1f2e0658',
                                                                                         'description': 'This '
                                                                                                        'test '
                                                                                                        'simulates '
                                                                                                        'an '
                                                                                                        'infected '
                                                                                                        'host '
                                                                                                        'beaconing '
                                                                                                        'to '
                                                                                                        'command '
                                                                                                        'and '
                                                                                                        'control.\n'
                                                                                                        'Inspired '
                                                                                                        'by '
                                                                                                        'APTSimulator '
                                                                                                        '- '
                                                                                                        'https://github.com/NextronSystems/APTSimulator/blob/master/test-sets/command-and-control/malicious-user-agents.bat\n',
                                                                                         'executor': {'command': 'curl '
                                                                                                                 '-s '
                                                                                                                 '-A '
                                                                                                                 '"HttpBrowser/1.0" '
                                                                                                                 '-m3 '
                                                                                                                 '#{domain}\n'
                                                                                                                 'curl '
                                                                                                                 '-s '
                                                                                                                 '-A '
                                                                                                                 '"Wget/1.9+cvs-stable '
                                                                                                                 '(Red '
                                                                                                                 'Hat '
                                                                                                                 'modified)" '
                                                                                                                 '-m3 '
                                                                                                                 '#{domain}\n'
                                                                                                                 'curl '
                                                                                                                 '-s '
                                                                                                                 '-A '
                                                                                                                 '"Opera/8.81 '
                                                                                                                 '(Windows '
                                                                                                                 'NT '
                                                                                                                 '6.0; '
                                                                                                                 'U; '
                                                                                                                 'en)" '
                                                                                                                 '-m3 '
                                                                                                                 '#{domain}\n'
                                                                                                                 'curl '
                                                                                                                 '-s '
                                                                                                                 '-A '
                                                                                                                 '"*<|>*" '
                                                                                                                 '-m3 '
                                                                                                                 '#{domain}\n',
                                                                                                      'name': 'sh'},
                                                                                         'input_arguments': {'domain': {'default': 'www.google.com',
                                                                                                                        'description': 'Default '
                                                                                                                                       'domain '
                                                                                                                                       'to '
                                                                                                                                       'simulate '
                                                                                                                                       'against',
                                                                                                                        'type': 'string'}},
                                                                                         'name': 'Malicious '
                                                                                                 'User '
                                                                                                 'Agents '
                                                                                                 '- '
                                                                                                 'Nix',
                                                                                         'supported_platforms': ['linux',
                                                                                                                 'macos']}],
                                                                       'attack_technique': 'T1071.001',
                                                                       'display_name': 'Application '
                                                                                       'Layer '
                                                                                       'Protocol: '
                                                                                       'Web '
                                                                                       'Protocols'}}]
```

# Tactics


* [Command and Control](../tactics/Command-and-Control.md)


# Mitigations


* [Network Intrusion Prevention](../mitigations/Network-Intrusion-Prevention.md)


# Actors


* [APT19](../actors/APT19.md)

* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [APT38](../actors/APT38.md)
    
* [APT18](../actors/APT18.md)
    
* [Stealth Falcon](../actors/Stealth-Falcon.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Rancor](../actors/Rancor.md)
    
* [Gamaredon Group](../actors/Gamaredon-Group.md)
    
* [APT37](../actors/APT37.md)
    
* [APT32](../actors/APT32.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Orangeworm](../actors/Orangeworm.md)
    
* [Turla](../actors/Turla.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [FIN4](../actors/FIN4.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [Dark Caracal](../actors/Dark-Caracal.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [APT33](../actors/APT33.md)
    
* [WIRTE](../actors/WIRTE.md)
    
* [APT28](../actors/APT28.md)
    
* [Machete](../actors/Machete.md)
    
* [SilverTerrier](../actors/SilverTerrier.md)
    
* [APT41](../actors/APT41.md)
    
* [Inception](../actors/Inception.md)
    
* [Wizard Spider](../actors/Wizard-Spider.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [APT39](../actors/APT39.md)
    
* [Rocke](../actors/Rocke.md)
    
* [TA505](../actors/TA505.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
