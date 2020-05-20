
# Credentials from Web Browsers

## Description

### MITRE Description

> Adversaries may acquire credentials from web browsers by reading files specific to the target browser.  (Citation: Talos Olympic Destroyer 2018) 

Web browsers commonly save credentials such as website usernames and passwords so that they do not need to be entered manually in the future. Web browsers typically store the credentials in an encrypted format within a credential store; however, methods exist to extract plaintext credentials from web browsers.

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
* Wiki: https://attack.mitre.org/techniques/T1503

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json

```

## Potential Queries

```json
[{'name': 'Yml',
  'product': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}',
  'query': 'Yml\n'
           'title: windows system web browser to obtain the voucher\n'
           'description: windows server 2016 test results\n'
           'references: No\n'
           'tags: T1503\n'
           'status: experimental\n'
           'author: 12306Bro\n'
           'logsource:\n'
           '\xa0\xa0\xa0\xa0product: windows\n'
           '\xa0\xa0\xa0\xa0service: security\n'
           'detection:\n'
           '\xa0\xa0\xa0\xa0selection:\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0EventID: 4663 # trying to access '
           'the object.\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Objectserver: Security # Object> '
           'Object Server\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Objecttype: file # Object> Object '
           'Type\n'
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Objectname:\n'
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0- 'C: \\ users \\ * \\ "
           'appdata \\ roaming \\ opera software \\ opera stable \\ login '
           "data' # Object> object name Opera\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0- 'C: \\ Users \\ "
           'IEUser \\ AppData \\ Roaming \\ Mozilla \\ Firefox \\ Profiles \\ '
           "kushu3sd.default \\ key4.db' #Firefox\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0- 'C: \\ Users \\ "
           'IEUser \\ AppData \\ Roaming \\ Mozilla \\ Firefox \\ Profiles \\ '
           "kushu3sd.default \\ logins.json' #Firefox\n"
           "\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0- 'C: \\ Users \\ "
           'IEUser \\ AppData \\ Local \\ Google \\ Chrome \\ User Data \\ '
           "Default \\ Login Data' #Chrome\n"
           '\xa0\xa0\xa0\xa0\xa0\xa0\xa0\xa0Access: ReadData (or '
           'listdirectory) # access request information> Access\n'
           '\xa0\xa0\xa0\xa0condition: selection\n'
           'level: medium'}]
```

## Raw Dataset

```json

```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations

None

# Actors


* [MuddyWater](../actors/MuddyWater.md)

* [Stolen Pencil](../actors/Stolen-Pencil.md)
    
* [TA505](../actors/TA505.md)
    
