
# Access Token Manipulation

## Description

### MITRE Description

> Windows uses access tokens to determine the ownership of a running process. A user can manipulate access tokens to make a running process appear as though it belongs to someone other than the user that started the process. When this occurs, the process also takes on the security context associated with the new token. For example, Microsoft promotes the use of access tokens as a security best practice. Administrators should log in as a standard user but run their tools with administrator privileges using the built-in access token manipulation command <code>runas</code>.(Citation: Microsoft runas)
  
Adversaries may use access tokens to operate under a different user or system security context to perform actions and evade detection. An adversary can use built-in Windows API functions to copy access tokens from existing processes; this is known as token stealing. An adversary must already be in a privileged user context (i.e. administrator) to steal a token. However, adversaries commonly use token stealing to elevate their security context from the administrator level to the SYSTEM level. An adversary can use a token to authenticate to a remote system as the account for that token if the account has appropriate permissions on the remote system.(Citation: Pentestlab Token Manipulation)

Access tokens can be leveraged by adversaries through three methods:(Citation: BlackHat Atkinson Winchester Token Manipulation)

**Token Impersonation/Theft** - An adversary creates a new access token that duplicates an existing token using <code>DuplicateToken(Ex)</code>. The token can then be used with <code>ImpersonateLoggedOnUser</code> to allow the calling thread to impersonate a logged on user's security context, or with <code>SetThreadToken</code> to assign the impersonated token to a thread. This is useful for when the target user has a non-network logon session on the system.

**Create Process with a Token** - An adversary creates a new access token with <code>DuplicateToken(Ex)</code> and uses it with <code>CreateProcessWithTokenW</code> to create a new process running under the security context of the impersonated user. This is useful for creating a new process under the security context of a different user.

**Make and Impersonate Token** - An adversary has a username and password but the user is not logged onto the system. The adversary can then create a logon session for the user using the <code>LogonUser</code> function. The function will return a copy of the new session's access token and the adversary can use <code>SetThreadToken</code> to assign the token to a thread.

Any standard user can use the <code>runas</code> command, and the Windows API functions, to create impersonation tokens; it does not require access to an administrator account.

Metasploit’s Meterpreter payload allows arbitrary token manipulation and uses token impersonation to escalate privileges.(Citation: Metasploit access token) The Cobalt Strike beacon payload allows arbitrary token impersonation and can also create tokens. (Citation: Cobalt Strike Access Token)

## Additional Attributes

* Bypass: None
* Effective Permissions: ['SYSTEM']
* Network: intentionally left blank
* Permissions: ['User', 'Administrator']
* Platforms: ['Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1134

## Potential Commands

```
Token Stealing:
steal_token pid#
Token Stealing:
use incognito
list_tokens -u
impersonate_token DOMAIN\\User
or:
steal_token {pid}
powershell/credentials/tokens
powershell/credentials/tokens
powershell/management/runas
powershell/management/runas
powershell/privesc/getsystem
powershell/privesc/getsystem
```

## Commands Dataset

```
[{'command': 'Token Stealing:\nsteal_token pid#',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'Token Stealing:\n'
             'use incognito\n'
             'list_tokens -u\n'
             'impersonate_token DOMAIN\\\\User\n'
             'or:\n'
             'steal_token {pid}',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'powershell/credentials/tokens',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/credentials/tokens',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/runas',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/runas',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/getsystem',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/privesc/getsystem',
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
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': '',
                                                  'Category': 'T1134',
                                                  'Cobalt Strike': 'Token '
                                                                   'Stealing:\n'
                                                                   'steal_token '
                                                                   'pid#',
                                                  'Description': 'This steals '
                                                                 'the access '
                                                                 'token from '
                                                                 'another '
                                                                 'process and '
                                                                 'uses it to '
                                                                 'gain access '
                                                                 'to other '
                                                                 'services or '
                                                                 'computers. '
                                                                 'In Cobalt '
                                                                 'Strike, this '
                                                                 'token is '
                                                                 'only used '
                                                                 'when '
                                                                 'accessing '
                                                                 'remote '
                                                                 'systems, but '
                                                                 'in '
                                                                 'Meterpreter, '
                                                                 'this token '
                                                                 'is used for '
                                                                 'everything '
                                                                 "until it's "
                                                                 'dropped via '
                                                                 'rev2self. '
                                                                 'You need to '
                                                                 'be in a high '
                                                                 'integrity '
                                                                 'process for '
                                                                 'this to '
                                                                 'work.',
                                                  'Metasploit': 'Token '
                                                                'Stealing:\n'
                                                                'use '
                                                                'incognito\n'
                                                                'list_tokens '
                                                                '-u\n'
                                                                'impersonate_token '
                                                                'DOMAIN\\\\User\n'
                                                                'or:\n'
                                                                'steal_token '
                                                                '{pid}'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1134',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/credentials/tokens":  '
                                                                                 '["T1134"],',
                                            'Empire Module': 'powershell/credentials/tokens',
                                            'Technique': 'Access Token '
                                                         'Manipulation'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1134',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/runas":  '
                                                                                 '["T1134"],',
                                            'Empire Module': 'powershell/management/runas',
                                            'Technique': 'Access Token '
                                                         'Manipulation'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1134',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/privesc/getsystem":  '
                                                                                 '["T1134"],',
                                            'Empire Module': 'powershell/privesc/getsystem',
                                            'Technique': 'Access Token '
                                                         'Manipulation'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations

None

# Actors


* [Lazarus Group](../actors/Lazarus-Group.md)

* [APT28](../actors/APT28.md)
    
* [Turla](../actors/Turla.md)
    
