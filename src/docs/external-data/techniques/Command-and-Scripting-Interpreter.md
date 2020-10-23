
# Command and Scripting Interpreter

## Description

### MITRE Description

> Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries. These interfaces and languages provide ways of interacting with computer systems and are a common feature across many different platforms. Most systems come with some built-in command-line interface and scripting capabilities, for example, macOS and Linux distributions include some flavor of [Unix Shell](https://attack.mitre.org/techniques/T1059/004) while Windows installations include the [Windows Command Shell](https://attack.mitre.org/techniques/T1059/003) and [PowerShell](https://attack.mitre.org/techniques/T1059/001).

There are also cross-platform interpreters such as [Python](https://attack.mitre.org/techniques/T1059/006), as well as those commonly associated with client applications such as [JavaScript/JScript](https://attack.mitre.org/techniques/T1059/007) and [Visual Basic](https://attack.mitre.org/techniques/T1059/005).

Adversaries may abuse these technologies in various ways as a means of executing arbitrary commands. Commands and scripts can be embedded in [Initial Access](https://attack.mitre.org/tactics/TA0001) payloads delivered to victims as lure documents or as secondary payloads downloaded from an existing C2. Adversaries may also execute commands through interactive terminals/shells.

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
* Wiki: https://attack.mitre.org/techniques/T1059

## Potential Commands

```
\\Windows\\.+\\cmd.exe
cmd.exe|/c
powershell/lateral_movement/invoke_sqloscmd
powershell/lateral_movement/invoke_sqloscmd
powershell/management/spawnas
powershell/management/spawnas
```

## Commands Dataset

```
[{'command': '\\\\Windows\\\\.+\\\\cmd.exe',
  'name': None,
  'source': 'SysmonHunter - Command-Line Interface'},
 {'command': 'cmd.exe|/c',
  'name': None,
  'source': 'SysmonHunter - Command-Line Interface'},
 {'command': 'powershell/lateral_movement/invoke_sqloscmd',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/lateral_movement/invoke_sqloscmd',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/spawnas',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/management/spawnas',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Florian Roth',
                  'description': 'Detects suspicious shell commands used in '
                                 'various Equation Group scripts and tools',
                  'detection': {'condition': 'keywords',
                                'keywords': ['chown root*chmod 4777 ',
                                             'cp /bin/sh .;chown',
                                             'chmod 4777 '
                                             '/tmp/.scsi/dev/bin/gsh',
                                             'chown root:root '
                                             '/tmp/.scsi/dev/bin/',
                                             'chown root:root x;',
                                             '/bin/telnet locip locport < '
                                             '/dev/console | /bin/sh',
                                             '/tmp/ratload',
                                             'ewok -t ',
                                             'xspy -display ',
                                             'cat > /dev/tcp/127.0.0.1/80 '
                                             '<<END',
                                             'rm -f '
                                             '/current/tmp/ftshell.latest',
                                             'ghost_* -v ',
                                             ' --wipe > /dev/null',
                                             'ping -c 2 *; grep * '
                                             '/proc/net/arp >/tmp/gx',
                                             'iptables * OUTPUT -p tcp -d '
                                             '127.0.0.1 --tcp-flags RST RST -j '
                                             'DROP;',
                                             '> /var/log/audit/audit.log; rm '
                                             '-f .',
                                             'cp /var/log/audit/audit.log .tmp',
                                             'sh >/dev/tcp/* <&1 2>&1',
                                             'ncat -vv -l -p * <',
                                             'nc -vv -l -p * <',
                                             '< /dev/console | uudecode && '
                                             'uncompress',
                                             'sendmail -osendmail;chmod +x '
                                             'sendmail',
                                             '/usr/bin/wget -O /tmp/a http* && '
                                             'chmod 755 /tmp/cron',
                                             'chmod 666 /var/run/utmp~',
                                             'chmod 700 nscd crond',
                                             'cp /etc/shadow /tmp/.',
                                             '</dev/console |uudecode > '
                                             '/dev/null 2>&1 && uncompress',
                                             'chmod 700 jp&&netstat -an|grep',
                                             'uudecode > /dev/null 2>&1 && '
                                             'uncompress -f * && chmod 755',
                                             'chmod 700 crond',
                                             'wget http*; chmod +x '
                                             '/tmp/sendmail',
                                             'chmod 700 fp sendmail pt',
                                             'chmod 755 /usr/vmsys/bin/pipe',
                                             'chmod -R 755 /usr/vmsys',
                                             'chmod 755 $opbin/*tunnel',
                                             'chmod 700 sendmail',
                                             'chmod 0700 sendmail',
                                             '/usr/bin/wget '
                                             'http*sendmail;chmod +x sendmail;',
                                             '&& telnet * 2>&1 </dev/console']},
                  'falsepositives': ['Unknown'],
                  'id': '41e5c73d-9983-4b69-bd03-e13b67e9623c',
                  'level': 'high',
                  'logsource': {'product': 'linux'},
                  'references': ['https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1'],
                  'tags': ['attack.execution', 'attack.g0020', 'attack.t1059'],
                  'title': 'Equation Group Indicators'}},
 {'data_source': {'author': 'Florian Roth',
                  'date': '2017/05/31',
                  'description': 'This events that are generated when using '
                                 'the hacktool Ruler by Sensepost',
                  'detection': {'condition': '(1 of selection*)',
                                'selection1': {'EventID': [4776],
                                               'Workstation': 'RULER'},
                                'selection2': {'EventID': [4624, 4625],
                                               'WorkstationName': 'RULER'}},
                  'falsepositives': ['Go utilities that use staaldraad awesome '
                                     'NTLM library'],
                  'id': '24549159-ac1b-479c-8175-d42aea947cae',
                  'level': 'high',
                  'logsource': {'product': 'windows', 'service': 'security'},
                  'modified': '2019/07/26',
                  'references': ['https://github.com/sensepost/ruler',
                                 'https://github.com/sensepost/ruler/issues/47',
                                 'https://github.com/staaldraad/go-ntlm/blob/master/ntlm/ntlmv1.go#L427',
                                 'https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4776',
                                 'https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624'],
                  'tags': ['attack.discovery',
                           'attack.execution',
                           'attack.t1087',
                           'attack.t1075',
                           'attack.t1114',
                           'attack.t1059'],
                  'title': 'Hacktool Ruler'}},
 {'data_source': {'author': 'Florian Roth',
                  'description': 'Detects a suspicious command line execution '
                                 'that includes an URL and AppData string in '
                                 'the command line parameters as used by '
                                 'several droppers (js/vbs > powershell)',
                  'detection': {'condition': 'selection',
                                'selection': {'CommandLine': ['cmd.exe /c '
                                                              '*http://*%AppData%',
                                                              'cmd.exe /c '
                                                              '*https://*%AppData%']}},
                  'falsepositives': ['High'],
                  'fields': ['CommandLine', 'ParentCommandLine'],
                  'id': '1ac8666b-046f-4201-8aba-1951aaec03a3',
                  'level': 'medium',
                  'logsource': {'category': 'process_creation',
                                'product': 'windows'},
                  'references': ['https://www.hybrid-analysis.com/sample/3a1f01206684410dbe8f1900bbeaaa543adfcd07368ba646b499fa5274b9edf6?environmentId=100',
                                 'https://www.hybrid-analysis.com/sample/f16c729aad5c74f19784a24257236a8bbe27f7cdc4a89806031ec7f1bebbd475?environmentId=100'],
                  'status': 'experimental',
                  'tags': ['attack.execution', 'attack.t1059'],
                  'title': 'Command Line Execution with suspicious URL and '
                           'AppData Strings'}},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['4688', 'Process Execution']}]
```

## Potential Queries

```json
[{'name': 'Command Line Interface',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and process_path contains "cmd.exe"'}]
```

## Raw Dataset

```json
[{'SysmonHunter - T1059': {'description': None,
                           'level': 'medium',
                           'name': 'Command-Line Interface',
                           'phase': 'Execution',
                           'query': [{'process': {'image': {'flag': 'regex',
                                                            'pattern': '\\\\Windows\\\\.+\\\\cmd.exe'}},
                                      'type': 'process'},
                                     {'process': {'cmdline': {'op': 'and',
                                                              'pattern': 'cmd.exe|/c'}},
                                      'type': 'process'}]}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1059',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/lateral_movement/invoke_sqloscmd":  '
                                                                                 '["T1059"],',
                                            'Empire Module': 'powershell/lateral_movement/invoke_sqloscmd',
                                            'Technique': 'Command-Line '
                                                         'Interface'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1059',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/management/spawnas":  '
                                                                                 '["T1059"],',
                                            'Empire Module': 'powershell/management/spawnas',
                                            'Technique': 'Command-Line '
                                                         'Interface'}}]
```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations


* [Execution Prevention](../mitigations/Execution-Prevention.md)

* [Code Signing](../mitigations/Code-Signing.md)
    
* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)
    
* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    
* [Antivirus/Antimalware](../mitigations/Antivirus-Antimalware.md)
    
* [Restrict Web-Based Content](../mitigations/Restrict-Web-Based-Content.md)
    

# Actors


* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)

* [Stealth Falcon](../actors/Stealth-Falcon.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [APT19](../actors/APT19.md)
    
* [FIN7](../actors/FIN7.md)
    
* [FIN6](../actors/FIN6.md)
    
* [FIN5](../actors/FIN5.md)
    
* [Whitefly](../actors/Whitefly.md)
    
* [Molerats](../actors/Molerats.md)
    
* [APT32](../actors/APT32.md)
    
