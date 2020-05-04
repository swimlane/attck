
# Web Service

## Description

### MITRE Description

> Adversaries may use an existing, legitimate external Web service as a means for relaying commands to a compromised system.

These commands may also include pointers to command and control (C2) infrastructure. Adversaries may post content, known as a dead drop resolver, on Web services with embedded (and often obfuscated/encoded) domains or IP addresses. Once infected, victims will reach out to and be redirected by these resolvers.

Popular websites and social media acting as a mechanism for C2 may give a significant amount of cover due to the likelihood that hosts within a network are already communicating with them prior to a compromise. Using common services, such as those offered by Google or Twitter, makes it easier for adversaries to hide in expected noise. Web service providers commonly use SSL/TLS encryption, giving adversaries an added level of protection.

Use of Web services may also protect back-end C2 infrastructure from discovery through malware binary analysis while also enabling operational resiliency (since this infrastructure may be dynamically changed).

## Additional Attributes

* Bypass: ['Binary Analysis', 'Log analysis', 'Firewall']
* Effective Permissions: None
* Network: True
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: intentionally left blank
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

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Web Service': {'atomic_tests': [{'description': 'Download '
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
                                                          {'description': 'Multiple '
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
    
