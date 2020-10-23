
# System Network Configuration Discovery

## Description

### MITRE Description

> Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems. Several operating system administration utilities exist that can be used to gather this information. Examples include [Arp](https://attack.mitre.org/software/S0099), [ipconfig](https://attack.mitre.org/software/S0100)/[ifconfig](https://attack.mitre.org/software/S0101), [nbtstat](https://attack.mitre.org/software/S0102), and [route](https://attack.mitre.org/software/S0103).

Adversaries may use the information from [System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016) during automated discovery to shape follow-on behaviors, including whether or not the adversary fully infects the target and/or attempts specific actions.

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
* Wiki: https://attack.mitre.org/techniques/T1016

## Potential Commands

```
ipconfig /all
shell ipconfig
ipconfig
post/windows/gather/enum_domains
arp -a
route print
shell arp -a
route
nbtstat -a {IP | COMP_NAME }
shell c:\windows\sysnative\nbstat.exe -a {IP | COMP_NAME}
ipconfig /all
netsh interface show interface
arp -a
nbtstat -n
net config

netsh advfirewall firewall show rule name=all

if [ -x "$(command -v arp)" ]; then arp -a; else echo "arp is missing from the machine. skipping..."; fi;
if [ -x "$(command -v ifconfig)" ]; then ifconfig; else echo "ifconfig is missing from the machine. skipping..."; fi;
if [ -x "$(command -v ip)" ]; then ip addr; else echo "ip is missing from the machine. skipping..."; fi;
if [ -x "$(command -v netstat)" ]; then netstat -ant | awk '{print $NF}' | grep -v '[a-z]' | sort | uniq -c; else echo "netstat is missing from the machine. skipping..."; fi;

ipconfig /all
net config workstation
net view /all /domain
nltest /domain_trusts

$ports = Get-content #{port_file}
$file = "$env:USERPROFILE\Desktop\open-ports.txt"
$totalopen = 0
$totalports = 0
New-Item $file -Force
foreach ($port in $ports) {
    $test = new-object system.Net.Sockets.TcpClient
    $wait = $test.beginConnect("allports.exposed", $port, $null, $null)
    $wait.asyncwaithandle.waitone(250, $false) | Out-Null
    $totalports++ | Out-Null
    if ($test.Connected) {
        $result = "$port open" 
        Write-Host -ForegroundColor Green $result
        $result | Out-File -Encoding ASCII -append $file
        $totalopen++ | Out-Null
    }
    else {
        $result = "$port closed" 
        Write-Host -ForegroundColor Red $result
        $totalclosed++ | Out-Null
        $result | Out-File -Encoding ASCII -append $file
    }
}
$results = "There were a total of $totalopen open ports out of $totalports ports tested."
$results | Out-File -Encoding ASCII -append $file
Write-Host $results

$ports = Get-content #{port_file}
$file = "#{output_file}"
$totalopen = 0
$totalports = 0
New-Item $file -Force
foreach ($port in $ports) {
    $test = new-object system.Net.Sockets.TcpClient
    $wait = $test.beginConnect("allports.exposed", $port, $null, $null)
    $wait.asyncwaithandle.waitone(250, $false) | Out-Null
    $totalports++ | Out-Null
    if ($test.Connected) {
        $result = "$port open" 
        Write-Host -ForegroundColor Green $result
        $result | Out-File -Encoding ASCII -append $file
        $totalopen++ | Out-Null
    }
    else {
        $result = "$port closed" 
        Write-Host -ForegroundColor Red $result
        $totalclosed++ | Out-Null
        $result | Out-File -Encoding ASCII -append $file
    }
}
$results = "There were a total of $totalopen open ports out of $totalports ports tested."
$results | Out-File -Encoding ASCII -append $file
Write-Host $results

$ports = Get-content PathToAtomicsFolder\T1016\src\top-128.txt
$file = "#{output_file}"
$totalopen = 0
$totalports = 0
New-Item $file -Force
foreach ($port in $ports) {
    $test = new-object system.Net.Sockets.TcpClient
    $wait = $test.beginConnect("allports.exposed", $port, $null, $null)
    $wait.asyncwaithandle.waitone(250, $false) | Out-Null
    $totalports++ | Out-Null
    if ($test.Connected) {
        $result = "$port open" 
        Write-Host -ForegroundColor Green $result
        $result | Out-File -Encoding ASCII -append $file
        $totalopen++ | Out-Null
    }
    else {
        $result = "$port closed" 
        Write-Host -ForegroundColor Red $result
        $totalclosed++ | Out-Null
        $result | Out-File -Encoding ASCII -append $file
    }
}
$results = "There were a total of $totalopen open ports out of $totalports ports tested."
$results | Out-File -Encoding ASCII -append $file
Write-Host $results

{'windows': {'psh': {'command': 'nbtstat -n\n', 'parsers': {'plugins.stockpile.app.parsers.nbtstat': [{'source': 'network.domain.name'}]}}}}
{'darwin': {'sh': {'command': './#{payload:9f639067-370a-40ba-b7ac-6f1c15d5a158} scan\n', 'payloads': ['9f639067-370a-40ba-b7ac-6f1c15d5a158']}}, 'linux': {'sh': {'command': './#{payload:9f639067-370a-40ba-b7ac-6f1c15d5a158} scan\n', 'payloads': ['9f639067-370a-40ba-b7ac-6f1c15d5a158']}}, 'windows': {'psh': {'command': '.\\#{payload:28f9bf43-4f14-4965-9bd9-b70fd6993d8e} -Scan\n', 'payloads': ['28f9bf43-4f14-4965-9bd9-b70fd6993d8e']}}}
{'darwin': {'sh': {'command': './wifi.sh pref\n', 'payloads': ['wifi.sh'], 'parsers': {'plugins.stockpile.app.parsers.wifipref': [{'source': 'wifi.network.ssid'}]}}}, 'linux': {'sh': {'command': './wifi.sh pref\n', 'payloads': ['wifi.sh'], 'parsers': {'plugins.stockpile.app.parsers.wifipref': [{'source': 'wifi.network.ssid'}]}}}, 'windows': {'psh': {'command': '.\\wifi.ps1 -Pref\n', 'payloads': ['wifi.ps1'], 'parsers': {'plugins.stockpile.app.parsers.wifipref': [{'source': 'wifi.network.ssid'}]}}}}
{'darwin': {'sh': {'command': 'for ip in $(seq 190 199); do ping -c 1 $(echo #{domain.broadcast.ip} |\ncut -d. -f-3).$ip -W 1; done\n'}}}
{'darwin': {'sh': {'command': 'ifconfig | grep broadcast'}}}
{'darwin': {'sh': {'command': 'sudo ifconfig\n'}}, 'linux': {'sh': {'command': 'sudo ifconfig\n'}}, 'windows': {'psh': {'command': 'ipconfig\n'}}}
powershell/situational_awareness/host/dnsserver
powershell/situational_awareness/host/dnsserver
powershell/situational_awareness/host/get_proxy
powershell/situational_awareness/host/get_proxy
powershell/situational_awareness/network/arpscan
powershell/situational_awareness/network/arpscan
powershell/situational_awareness/network/powerview/get_subnet
powershell/situational_awareness/network/powerview/get_subnet
```

## Commands Dataset

```
[{'command': 'ipconfig /all',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'shell ipconfig',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'ipconfig\npost/windows/gather/enum_domains',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'arp -a\nroute print',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'shell arp -a',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'route',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'nbtstat -a {IP | COMP_NAME }',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'shell c:\\windows\\sysnative\\nbstat.exe -a {IP | COMP_NAME}',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'ipconfig /all\n'
             'netsh interface show interface\n'
             'arp -a\n'
             'nbtstat -n\n'
             'net config\n',
  'name': None,
  'source': 'atomics/T1016/T1016.yaml'},
 {'command': 'netsh advfirewall firewall show rule name=all\n',
  'name': None,
  'source': 'atomics/T1016/T1016.yaml'},
 {'command': 'if [ -x "$(command -v arp)" ]; then arp -a; else echo "arp is '
             'missing from the machine. skipping..."; fi;\n'
             'if [ -x "$(command -v ifconfig)" ]; then ifconfig; else echo '
             '"ifconfig is missing from the machine. skipping..."; fi;\n'
             'if [ -x "$(command -v ip)" ]; then ip addr; else echo "ip is '
             'missing from the machine. skipping..."; fi;\n'
             'if [ -x "$(command -v netstat)" ]; then netstat -ant | awk '
             "'{print $NF}' | grep -v '[a-z]' | sort | uniq -c; else echo "
             '"netstat is missing from the machine. skipping..."; fi;\n',
  'name': None,
  'source': 'atomics/T1016/T1016.yaml'},
 {'command': 'ipconfig /all\n'
             'net config workstation\n'
             'net view /all /domain\n'
             'nltest /domain_trusts\n',
  'name': None,
  'source': 'atomics/T1016/T1016.yaml'},
 {'command': '$ports = Get-content #{port_file}\n'
             '$file = "$env:USERPROFILE\\Desktop\\open-ports.txt"\n'
             '$totalopen = 0\n'
             '$totalports = 0\n'
             'New-Item $file -Force\n'
             'foreach ($port in $ports) {\n'
             '    $test = new-object system.Net.Sockets.TcpClient\n'
             '    $wait = $test.beginConnect("allports.exposed", $port, $null, '
             '$null)\n'
             '    $wait.asyncwaithandle.waitone(250, $false) | Out-Null\n'
             '    $totalports++ | Out-Null\n'
             '    if ($test.Connected) {\n'
             '        $result = "$port open" \n'
             '        Write-Host -ForegroundColor Green $result\n'
             '        $result | Out-File -Encoding ASCII -append $file\n'
             '        $totalopen++ | Out-Null\n'
             '    }\n'
             '    else {\n'
             '        $result = "$port closed" \n'
             '        Write-Host -ForegroundColor Red $result\n'
             '        $totalclosed++ | Out-Null\n'
             '        $result | Out-File -Encoding ASCII -append $file\n'
             '    }\n'
             '}\n'
             '$results = "There were a total of $totalopen open ports out of '
             '$totalports ports tested."\n'
             '$results | Out-File -Encoding ASCII -append $file\n'
             'Write-Host $results\n',
  'name': None,
  'source': 'atomics/T1016/T1016.yaml'},
 {'command': '$ports = Get-content #{port_file}\n'
             '$file = "#{output_file}"\n'
             '$totalopen = 0\n'
             '$totalports = 0\n'
             'New-Item $file -Force\n'
             'foreach ($port in $ports) {\n'
             '    $test = new-object system.Net.Sockets.TcpClient\n'
             '    $wait = $test.beginConnect("allports.exposed", $port, $null, '
             '$null)\n'
             '    $wait.asyncwaithandle.waitone(250, $false) | Out-Null\n'
             '    $totalports++ | Out-Null\n'
             '    if ($test.Connected) {\n'
             '        $result = "$port open" \n'
             '        Write-Host -ForegroundColor Green $result\n'
             '        $result | Out-File -Encoding ASCII -append $file\n'
             '        $totalopen++ | Out-Null\n'
             '    }\n'
             '    else {\n'
             '        $result = "$port closed" \n'
             '        Write-Host -ForegroundColor Red $result\n'
             '        $totalclosed++ | Out-Null\n'
             '        $result | Out-File -Encoding ASCII -append $file\n'
             '    }\n'
             '}\n'
             '$results = "There were a total of $totalopen open ports out of '
             '$totalports ports tested."\n'
             '$results | Out-File -Encoding ASCII -append $file\n'
             'Write-Host $results\n',
  'name': None,
  'source': 'atomics/T1016/T1016.yaml'},
 {'command': '$ports = Get-content '
             'PathToAtomicsFolder\\T1016\\src\\top-128.txt\n'
             '$file = "#{output_file}"\n'
             '$totalopen = 0\n'
             '$totalports = 0\n'
             'New-Item $file -Force\n'
             'foreach ($port in $ports) {\n'
             '    $test = new-object system.Net.Sockets.TcpClient\n'
             '    $wait = $test.beginConnect("allports.exposed", $port, $null, '
             '$null)\n'
             '    $wait.asyncwaithandle.waitone(250, $false) | Out-Null\n'
             '    $totalports++ | Out-Null\n'
             '    if ($test.Connected) {\n'
             '        $result = "$port open" \n'
             '        Write-Host -ForegroundColor Green $result\n'
             '        $result | Out-File -Encoding ASCII -append $file\n'
             '        $totalopen++ | Out-Null\n'
             '    }\n'
             '    else {\n'
             '        $result = "$port closed" \n'
             '        Write-Host -ForegroundColor Red $result\n'
             '        $totalclosed++ | Out-Null\n'
             '        $result | Out-File -Encoding ASCII -append $file\n'
             '    }\n'
             '}\n'
             '$results = "There were a total of $totalopen open ports out of '
             '$totalports ports tested."\n'
             '$results | Out-File -Encoding ASCII -append $file\n'
             'Write-Host $results\n',
  'name': None,
  'source': 'atomics/T1016/T1016.yaml'},
 {'command': {'windows': {'psh': {'command': 'nbtstat -n\n',
                                  'parsers': {'plugins.stockpile.app.parsers.nbtstat': [{'source': 'network.domain.name'}]}}}},
  'name': 'Find Domain information',
  'source': 'data/abilities/discovery/14a21534-350f-4d83-9dd7-3c56b93a0c17.yml'},
 {'command': {'darwin': {'sh': {'command': './#{payload:9f639067-370a-40ba-b7ac-6f1c15d5a158} '
                                           'scan\n',
                                'payloads': ['9f639067-370a-40ba-b7ac-6f1c15d5a158']}},
              'linux': {'sh': {'command': './#{payload:9f639067-370a-40ba-b7ac-6f1c15d5a158} '
                                          'scan\n',
                               'payloads': ['9f639067-370a-40ba-b7ac-6f1c15d5a158']}},
              'windows': {'psh': {'command': '.\\#{payload:28f9bf43-4f14-4965-9bd9-b70fd6993d8e} '
                                             '-Scan\n',
                                  'payloads': ['28f9bf43-4f14-4965-9bd9-b70fd6993d8e']}}},
  'name': 'View all potential WIFI networks on host',
  'source': 'data/abilities/discovery/9a30740d-3aa8-4c23-8efa-d51215e8a5b9.yml'},
 {'command': {'darwin': {'sh': {'command': './wifi.sh pref\n',
                                'parsers': {'plugins.stockpile.app.parsers.wifipref': [{'source': 'wifi.network.ssid'}]},
                                'payloads': ['wifi.sh']}},
              'linux': {'sh': {'command': './wifi.sh pref\n',
                               'parsers': {'plugins.stockpile.app.parsers.wifipref': [{'source': 'wifi.network.ssid'}]},
                               'payloads': ['wifi.sh']}},
              'windows': {'psh': {'command': '.\\wifi.ps1 -Pref\n',
                                  'parsers': {'plugins.stockpile.app.parsers.wifipref': [{'source': 'wifi.network.ssid'}]},
                                  'payloads': ['wifi.ps1']}}},
  'name': 'See the most used WIFI networks of a machine',
  'source': 'data/abilities/discovery/a0676fe1-cd52-482e-8dde-349b73f9aa69.yml'},
 {'command': {'darwin': {'sh': {'command': 'for ip in $(seq 190 199); do ping '
                                           '-c 1 $(echo #{domain.broadcast.ip} '
                                           '|\n'
                                           'cut -d. -f-3).$ip -W 1; done\n'}}},
  'name': 'Ping the network in order to build the ARP cache',
  'source': 'data/abilities/discovery/ac9dce33-2acc-4b34-94ce-2596409ce8f0.yml'},
 {'command': {'darwin': {'sh': {'command': 'ifconfig | grep broadcast'}}},
  'name': 'Capture the local network broadcast IP address',
  'source': 'data/abilities/discovery/b6f545ef-f802-4537-b59d-2cb19831c8ed.yml'},
 {'command': {'darwin': {'sh': {'command': 'sudo ifconfig\n'}},
              'linux': {'sh': {'command': 'sudo ifconfig\n'}},
              'windows': {'psh': {'command': 'ipconfig\n'}}},
  'name': 'View network configuration info for host',
  'source': 'data/abilities/discovery/e8017c46-acb8-400c-a4b5-b3362b5b5baa.yml'},
 {'command': 'powershell/situational_awareness/host/dnsserver',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/host/dnsserver',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/host/get_proxy',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/host/get_proxy',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/arpscan',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/arpscan',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_subnet',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_subnet',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['200-500', ' 4100-4104', 'PowerShell']},
 {'data_source': ['5861', 'WMI']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['5861', 'WMI']},
 {'data_source': ['200-500', ' 4100-4104', 'PowerShell']}]
```

## Potential Queries

```json
[{'name': 'System Network Configuration Discovery',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 1 and (process_command_line contains '
           '"net.exe"and file_directory contains "config")or '
           '(process_command_line contains "ipconfig.exe"or '
           'process_command_line contains "netsh.exe"or process_command_line '
           'contains "arp.exe"or process_command_line contains "nbtstat.exe")'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'ipconfig '
                                                                              '/all',
                                                  'Category': 'T1016',
                                                  'Cobalt Strike': 'shell '
                                                                   'ipconfig',
                                                  'Description': 'Get '
                                                                 'information '
                                                                 'about the '
                                                                 'domain, '
                                                                 'network '
                                                                 'adapters, '
                                                                 'DNS / WSUS '
                                                                 'servers',
                                                  'Metasploit': 'ipconfig\n'
                                                                'post/windows/gather/enum_domains'}},
 {'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'arp '
                                                                              '-a\n'
                                                                              'route '
                                                                              'print',
                                                  'Category': 'T1016',
                                                  'Cobalt Strike': 'shell arp '
                                                                   '-a',
                                                  'Description': 'Display the '
                                                                 'ARP table',
                                                  'Metasploit': 'route'}},
 {'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'nbtstat '
                                                                              '-a '
                                                                              '{IP '
                                                                              '| '
                                                                              'COMP_NAME '
                                                                              '}',
                                                  'Category': 'T1016',
                                                  'Cobalt Strike': 'shell '
                                                                   'c:\\windows\\sysnative\\nbstat.exe '
                                                                   '-a {IP | '
                                                                   'COMP_NAME}',
                                                  'Description': 'Used to get '
                                                                 'the MAC and '
                                                                 'IP addresses '
                                                                 'as well as '
                                                                 'some '
                                                                 'descriptive '
                                                                 'codes for '
                                                                 'machines '
                                                                 '(0x1C '
                                                                 'indicates a '
                                                                 'domain '
                                                                 'controller)',
                                                  'Metasploit': ''}},
 {'Atomic Red Team Test - System Network Configuration Discovery': {'atomic_tests': [{'auto_generated_guid': '970ab6a1-0157-4f3f-9a73-ec4166754b23',
                                                                                      'description': 'Identify '
                                                                                                     'network '
                                                                                                     'configuration '
                                                                                                     'information\n'
                                                                                                     '\n'
                                                                                                     'Upon '
                                                                                                     'successful '
                                                                                                     'execution, '
                                                                                                     'cmd.exe '
                                                                                                     'will '
                                                                                                     'spawn '
                                                                                                     'multiple '
                                                                                                     'commands '
                                                                                                     'to '
                                                                                                     'list '
                                                                                                     'network '
                                                                                                     'configuration '
                                                                                                     'settings. '
                                                                                                     'Output '
                                                                                                     'will '
                                                                                                     'be '
                                                                                                     'via '
                                                                                                     'stdout.\n',
                                                                                      'executor': {'command': 'ipconfig '
                                                                                                              '/all\n'
                                                                                                              'netsh '
                                                                                                              'interface '
                                                                                                              'show '
                                                                                                              'interface\n'
                                                                                                              'arp '
                                                                                                              '-a\n'
                                                                                                              'nbtstat '
                                                                                                              '-n\n'
                                                                                                              'net '
                                                                                                              'config\n',
                                                                                                   'name': 'command_prompt'},
                                                                                      'name': 'System '
                                                                                              'Network '
                                                                                              'Configuration '
                                                                                              'Discovery '
                                                                                              'on '
                                                                                              'Windows',
                                                                                      'supported_platforms': ['windows']},
                                                                                     {'auto_generated_guid': '038263cb-00f4-4b0a-98ae-0696c67e1752',
                                                                                      'description': 'Enumerates '
                                                                                                     'Windows '
                                                                                                     'Firewall '
                                                                                                     'Rules '
                                                                                                     'using '
                                                                                                     'netsh.\n'
                                                                                                     '\n'
                                                                                                     'Upon '
                                                                                                     'successful '
                                                                                                     'execution, '
                                                                                                     'cmd.exe '
                                                                                                     'will '
                                                                                                     'spawn '
                                                                                                     'netsh.exe '
                                                                                                     'to '
                                                                                                     'list '
                                                                                                     'firewall '
                                                                                                     'rules. '
                                                                                                     'Output '
                                                                                                     'will '
                                                                                                     'be '
                                                                                                     'via '
                                                                                                     'stdout.\n',
                                                                                      'executor': {'command': 'netsh '
                                                                                                              'advfirewall '
                                                                                                              'firewall '
                                                                                                              'show '
                                                                                                              'rule '
                                                                                                              'name=all\n',
                                                                                                   'name': 'command_prompt'},
                                                                                      'name': 'List '
                                                                                              'Windows '
                                                                                              'Firewall '
                                                                                              'Rules',
                                                                                      'supported_platforms': ['windows']},
                                                                                     {'auto_generated_guid': 'c141bbdb-7fca-4254-9fd6-f47e79447e17',
                                                                                      'description': 'Identify '
                                                                                                     'network '
                                                                                                     'configuration '
                                                                                                     'information.\n'
                                                                                                     '\n'
                                                                                                     'Upon '
                                                                                                     'successful '
                                                                                                     'execution, '
                                                                                                     'sh '
                                                                                                     'will '
                                                                                                     'spawn '
                                                                                                     'multiple '
                                                                                                     'commands '
                                                                                                     'and '
                                                                                                     'output '
                                                                                                     'will '
                                                                                                     'be '
                                                                                                     'via '
                                                                                                     'stdout.\n',
                                                                                      'executor': {'command': 'if '
                                                                                                              '[ '
                                                                                                              '-x '
                                                                                                              '"$(command '
                                                                                                              '-v '
                                                                                                              'arp)" '
                                                                                                              ']; '
                                                                                                              'then '
                                                                                                              'arp '
                                                                                                              '-a; '
                                                                                                              'else '
                                                                                                              'echo '
                                                                                                              '"arp '
                                                                                                              'is '
                                                                                                              'missing '
                                                                                                              'from '
                                                                                                              'the '
                                                                                                              'machine. '
                                                                                                              'skipping..."; '
                                                                                                              'fi;\n'
                                                                                                              'if '
                                                                                                              '[ '
                                                                                                              '-x '
                                                                                                              '"$(command '
                                                                                                              '-v '
                                                                                                              'ifconfig)" '
                                                                                                              ']; '
                                                                                                              'then '
                                                                                                              'ifconfig; '
                                                                                                              'else '
                                                                                                              'echo '
                                                                                                              '"ifconfig '
                                                                                                              'is '
                                                                                                              'missing '
                                                                                                              'from '
                                                                                                              'the '
                                                                                                              'machine. '
                                                                                                              'skipping..."; '
                                                                                                              'fi;\n'
                                                                                                              'if '
                                                                                                              '[ '
                                                                                                              '-x '
                                                                                                              '"$(command '
                                                                                                              '-v '
                                                                                                              'ip)" '
                                                                                                              ']; '
                                                                                                              'then '
                                                                                                              'ip '
                                                                                                              'addr; '
                                                                                                              'else '
                                                                                                              'echo '
                                                                                                              '"ip '
                                                                                                              'is '
                                                                                                              'missing '
                                                                                                              'from '
                                                                                                              'the '
                                                                                                              'machine. '
                                                                                                              'skipping..."; '
                                                                                                              'fi;\n'
                                                                                                              'if '
                                                                                                              '[ '
                                                                                                              '-x '
                                                                                                              '"$(command '
                                                                                                              '-v '
                                                                                                              'netstat)" '
                                                                                                              ']; '
                                                                                                              'then '
                                                                                                              'netstat '
                                                                                                              '-ant '
                                                                                                              '| '
                                                                                                              'awk '
                                                                                                              "'{print "
                                                                                                              "$NF}' "
                                                                                                              '| '
                                                                                                              'grep '
                                                                                                              '-v '
                                                                                                              "'[a-z]' "
                                                                                                              '| '
                                                                                                              'sort '
                                                                                                              '| '
                                                                                                              'uniq '
                                                                                                              '-c; '
                                                                                                              'else '
                                                                                                              'echo '
                                                                                                              '"netstat '
                                                                                                              'is '
                                                                                                              'missing '
                                                                                                              'from '
                                                                                                              'the '
                                                                                                              'machine. '
                                                                                                              'skipping..."; '
                                                                                                              'fi;\n',
                                                                                                   'name': 'sh'},
                                                                                      'name': 'System '
                                                                                              'Network '
                                                                                              'Configuration '
                                                                                              'Discovery',
                                                                                      'supported_platforms': ['macos',
                                                                                                              'linux']},
                                                                                     {'auto_generated_guid': 'dafaf052-5508-402d-bf77-51e0700c02e2',
                                                                                      'description': 'Identify '
                                                                                                     'network '
                                                                                                     'configuration '
                                                                                                     'information '
                                                                                                     'as '
                                                                                                     'seen '
                                                                                                     'by '
                                                                                                     'Trickbot '
                                                                                                     'and '
                                                                                                     'described '
                                                                                                     'here '
                                                                                                     'https://www.sneakymonkey.net/2019/10/29/trickbot-analysis-part-ii/\n'
                                                                                                     '\n'
                                                                                                     'Upon '
                                                                                                     'successful '
                                                                                                     'execution, '
                                                                                                     'cmd.exe '
                                                                                                     'will '
                                                                                                     'spawn '
                                                                                                     '`ipconfig '
                                                                                                     '/all`, '
                                                                                                     '`net '
                                                                                                     'config '
                                                                                                     'workstation`, '
                                                                                                     '`net '
                                                                                                     'view '
                                                                                                     '/all '
                                                                                                     '/domain`, '
                                                                                                     '`nltest '
                                                                                                     '/domain_trusts`. '
                                                                                                     'Output '
                                                                                                     'will '
                                                                                                     'be '
                                                                                                     'via '
                                                                                                     'stdout.\n',
                                                                                      'executor': {'command': 'ipconfig '
                                                                                                              '/all\n'
                                                                                                              'net '
                                                                                                              'config '
                                                                                                              'workstation\n'
                                                                                                              'net '
                                                                                                              'view '
                                                                                                              '/all '
                                                                                                              '/domain\n'
                                                                                                              'nltest '
                                                                                                              '/domain_trusts\n',
                                                                                                   'name': 'command_prompt'},
                                                                                      'name': 'System '
                                                                                              'Network '
                                                                                              'Configuration '
                                                                                              'Discovery '
                                                                                              '(TrickBot '
                                                                                              'Style)',
                                                                                      'supported_platforms': ['windows']},
                                                                                     {'auto_generated_guid': '4b467538-f102-491d-ace7-ed487b853bf5',
                                                                                      'dependencies': [{'description': 'Test '
                                                                                                                       'requires '
                                                                                                                       '#{port_file} '
                                                                                                                       'to '
                                                                                                                       'exist\n',
                                                                                                        'get_prereq_command': 'New-Item '
                                                                                                                              '-Type '
                                                                                                                              'Directory '
                                                                                                                              '(split-path '
                                                                                                                              '#{port_file}) '
                                                                                                                              '-ErrorAction '
                                                                                                                              'ignore '
                                                                                                                              '| '
                                                                                                                              'Out-Null\n'
                                                                                                                              'Invoke-WebRequest '
                                                                                                                              '"#{portfile_url}" '
                                                                                                                              '-OutFile '
                                                                                                                              '"#{port_file}"\n',
                                                                                                        'prereq_command': 'if '
                                                                                                                          '(Test-Path '
                                                                                                                          '"#{port_file}") '
                                                                                                                          '{exit '
                                                                                                                          '0} '
                                                                                                                          'else '
                                                                                                                          '{exit '
                                                                                                                          '1}\n'}],
                                                                                      'dependency_executor_name': 'powershell',
                                                                                      'description': 'This '
                                                                                                     'is '
                                                                                                     'to '
                                                                                                     'test '
                                                                                                     'for '
                                                                                                     'what '
                                                                                                     'ports '
                                                                                                     'are '
                                                                                                     'open '
                                                                                                     'outbound.  '
                                                                                                     'The '
                                                                                                     'technique '
                                                                                                     'used '
                                                                                                     'was '
                                                                                                     'taken '
                                                                                                     'from '
                                                                                                     'the '
                                                                                                     'following '
                                                                                                     'blog:\n'
                                                                                                     'https://www.blackhillsinfosec.com/poking-holes-in-the-firewall-egress-testing-with-allports-exposed/\n'
                                                                                                     '\n'
                                                                                                     'Upon '
                                                                                                     'successful '
                                                                                                     'execution, '
                                                                                                     'powershell '
                                                                                                     'will '
                                                                                                     'read '
                                                                                                     'top-128.txt '
                                                                                                     '(ports) '
                                                                                                     'and '
                                                                                                     'contact '
                                                                                                     'each '
                                                                                                     'port '
                                                                                                     'to '
                                                                                                     'confirm '
                                                                                                     'if '
                                                                                                     'open '
                                                                                                     'or '
                                                                                                     'not. '
                                                                                                     'Output '
                                                                                                     'will '
                                                                                                     'be '
                                                                                                     'to '
                                                                                                     'Desktop\\open-ports.txt.\n',
                                                                                      'executor': {'cleanup_command': 'Remove-Item '
                                                                                                                      '-ErrorAction '
                                                                                                                      'ignore '
                                                                                                                      '"#{output_file}"\n',
                                                                                                   'command': '$ports '
                                                                                                              '= '
                                                                                                              'Get-content '
                                                                                                              '#{port_file}\n'
                                                                                                              '$file '
                                                                                                              '= '
                                                                                                              '"#{output_file}"\n'
                                                                                                              '$totalopen '
                                                                                                              '= '
                                                                                                              '0\n'
                                                                                                              '$totalports '
                                                                                                              '= '
                                                                                                              '0\n'
                                                                                                              'New-Item '
                                                                                                              '$file '
                                                                                                              '-Force\n'
                                                                                                              'foreach '
                                                                                                              '($port '
                                                                                                              'in '
                                                                                                              '$ports) '
                                                                                                              '{\n'
                                                                                                              '    '
                                                                                                              '$test '
                                                                                                              '= '
                                                                                                              'new-object '
                                                                                                              'system.Net.Sockets.TcpClient\n'
                                                                                                              '    '
                                                                                                              '$wait '
                                                                                                              '= '
                                                                                                              '$test.beginConnect("allports.exposed", '
                                                                                                              '$port, '
                                                                                                              '$null, '
                                                                                                              '$null)\n'
                                                                                                              '    '
                                                                                                              '$wait.asyncwaithandle.waitone(250, '
                                                                                                              '$false) '
                                                                                                              '| '
                                                                                                              'Out-Null\n'
                                                                                                              '    '
                                                                                                              '$totalports++ '
                                                                                                              '| '
                                                                                                              'Out-Null\n'
                                                                                                              '    '
                                                                                                              'if '
                                                                                                              '($test.Connected) '
                                                                                                              '{\n'
                                                                                                              '        '
                                                                                                              '$result '
                                                                                                              '= '
                                                                                                              '"$port '
                                                                                                              'open" \n'
                                                                                                              '        '
                                                                                                              'Write-Host '
                                                                                                              '-ForegroundColor '
                                                                                                              'Green '
                                                                                                              '$result\n'
                                                                                                              '        '
                                                                                                              '$result '
                                                                                                              '| '
                                                                                                              'Out-File '
                                                                                                              '-Encoding '
                                                                                                              'ASCII '
                                                                                                              '-append '
                                                                                                              '$file\n'
                                                                                                              '        '
                                                                                                              '$totalopen++ '
                                                                                                              '| '
                                                                                                              'Out-Null\n'
                                                                                                              '    '
                                                                                                              '}\n'
                                                                                                              '    '
                                                                                                              'else '
                                                                                                              '{\n'
                                                                                                              '        '
                                                                                                              '$result '
                                                                                                              '= '
                                                                                                              '"$port '
                                                                                                              'closed" \n'
                                                                                                              '        '
                                                                                                              'Write-Host '
                                                                                                              '-ForegroundColor '
                                                                                                              'Red '
                                                                                                              '$result\n'
                                                                                                              '        '
                                                                                                              '$totalclosed++ '
                                                                                                              '| '
                                                                                                              'Out-Null\n'
                                                                                                              '        '
                                                                                                              '$result '
                                                                                                              '| '
                                                                                                              'Out-File '
                                                                                                              '-Encoding '
                                                                                                              'ASCII '
                                                                                                              '-append '
                                                                                                              '$file\n'
                                                                                                              '    '
                                                                                                              '}\n'
                                                                                                              '}\n'
                                                                                                              '$results '
                                                                                                              '= '
                                                                                                              '"There '
                                                                                                              'were '
                                                                                                              'a '
                                                                                                              'total '
                                                                                                              'of '
                                                                                                              '$totalopen '
                                                                                                              'open '
                                                                                                              'ports '
                                                                                                              'out '
                                                                                                              'of '
                                                                                                              '$totalports '
                                                                                                              'ports '
                                                                                                              'tested."\n'
                                                                                                              '$results '
                                                                                                              '| '
                                                                                                              'Out-File '
                                                                                                              '-Encoding '
                                                                                                              'ASCII '
                                                                                                              '-append '
                                                                                                              '$file\n'
                                                                                                              'Write-Host '
                                                                                                              '$results\n',
                                                                                                   'name': 'powershell'},
                                                                                      'input_arguments': {'output_file': {'default': '$env:USERPROFILE\\Desktop\\open-ports.txt',
                                                                                                                          'description': 'Path '
                                                                                                                                         'of '
                                                                                                                                         'file '
                                                                                                                                         'to '
                                                                                                                                         'write '
                                                                                                                                         'port '
                                                                                                                                         'scan '
                                                                                                                                         'results',
                                                                                                                          'type': 'Path'},
                                                                                                          'port_file': {'default': 'PathToAtomicsFolder\\T1016\\src\\top-128.txt',
                                                                                                                        'description': 'The '
                                                                                                                                       'path '
                                                                                                                                       'to '
                                                                                                                                       'a '
                                                                                                                                       'text '
                                                                                                                                       'file '
                                                                                                                                       'containing '
                                                                                                                                       'ports '
                                                                                                                                       'to '
                                                                                                                                       'be '
                                                                                                                                       'scanned, '
                                                                                                                                       'one '
                                                                                                                                       'port '
                                                                                                                                       'per '
                                                                                                                                       'line. '
                                                                                                                                       'The '
                                                                                                                                       'default '
                                                                                                                                       'list '
                                                                                                                                       'uses '
                                                                                                                                       'the '
                                                                                                                                       'top '
                                                                                                                                       '128 '
                                                                                                                                       'ports '
                                                                                                                                       'as '
                                                                                                                                       'defined '
                                                                                                                                       'by '
                                                                                                                                       'Nmap.',
                                                                                                                        'type': 'Path'},
                                                                                                          'portfile_url': {'default': 'https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1016/src/top-128.txt',
                                                                                                                           'description': 'URL '
                                                                                                                                          'to '
                                                                                                                                          'top-128.txt',
                                                                                                                           'type': 'Url'}},
                                                                                      'name': 'List '
                                                                                              'Open '
                                                                                              'Egress '
                                                                                              'Ports',
                                                                                      'supported_platforms': ['windows']}],
                                                                    'attack_technique': 'T1016',
                                                                    'display_name': 'System '
                                                                                    'Network '
                                                                                    'Configuration '
                                                                                    'Discovery'}},
 {'Mitre Stockpile - Find Domain information': {'description': 'Find Domain '
                                                               'information',
                                                'id': '14a21534-350f-4d83-9dd7-3c56b93a0c17',
                                                'name': 'Find Domain',
                                                'platforms': {'windows': {'psh': {'command': 'nbtstat '
                                                                                             '-n\n',
                                                                                  'parsers': {'plugins.stockpile.app.parsers.nbtstat': [{'source': 'network.domain.name'}]}}}},
                                                'tactic': 'discovery',
                                                'technique': {'attack_id': 'T1016',
                                                              'name': 'System '
                                                                      'Network '
                                                                      'Configuration '
                                                                      'Discovery'}}},
 {'Mitre Stockpile - View all potential WIFI networks on host': {'description': 'View '
                                                                                'all '
                                                                                'potential '
                                                                                'WIFI '
                                                                                'networks '
                                                                                'on '
                                                                                'host',
                                                                 'id': '9a30740d-3aa8-4c23-8efa-d51215e8a5b9',
                                                                 'name': 'Scan '
                                                                         'WIFI '
                                                                         'networks',
                                                                 'platforms': {'darwin': {'sh': {'command': './#{payload:9f639067-370a-40ba-b7ac-6f1c15d5a158} '
                                                                                                            'scan\n',
                                                                                                 'payloads': ['9f639067-370a-40ba-b7ac-6f1c15d5a158']}},
                                                                               'linux': {'sh': {'command': './#{payload:9f639067-370a-40ba-b7ac-6f1c15d5a158} '
                                                                                                           'scan\n',
                                                                                                'payloads': ['9f639067-370a-40ba-b7ac-6f1c15d5a158']}},
                                                                               'windows': {'psh': {'command': '.\\#{payload:28f9bf43-4f14-4965-9bd9-b70fd6993d8e} '
                                                                                                              '-Scan\n',
                                                                                                   'payloads': ['28f9bf43-4f14-4965-9bd9-b70fd6993d8e']}}},
                                                                 'tactic': 'discovery',
                                                                 'technique': {'attack_id': 'T1016',
                                                                               'name': 'System '
                                                                                       'Network '
                                                                                       'Configuration '
                                                                                       'Discovery'}}},
 {'Mitre Stockpile - See the most used WIFI networks of a machine': {'description': 'See '
                                                                                    'the '
                                                                                    'most '
                                                                                    'used '
                                                                                    'WIFI '
                                                                                    'networks '
                                                                                    'of '
                                                                                    'a '
                                                                                    'machine',
                                                                     'id': 'a0676fe1-cd52-482e-8dde-349b73f9aa69',
                                                                     'name': 'Preferred '
                                                                             'WIFI',
                                                                     'platforms': {'darwin': {'sh': {'command': './wifi.sh '
                                                                                                                'pref\n',
                                                                                                     'parsers': {'plugins.stockpile.app.parsers.wifipref': [{'source': 'wifi.network.ssid'}]},
                                                                                                     'payloads': ['wifi.sh']}},
                                                                                   'linux': {'sh': {'command': './wifi.sh '
                                                                                                               'pref\n',
                                                                                                    'parsers': {'plugins.stockpile.app.parsers.wifipref': [{'source': 'wifi.network.ssid'}]},
                                                                                                    'payloads': ['wifi.sh']}},
                                                                                   'windows': {'psh': {'command': '.\\wifi.ps1 '
                                                                                                                  '-Pref\n',
                                                                                                       'parsers': {'plugins.stockpile.app.parsers.wifipref': [{'source': 'wifi.network.ssid'}]},
                                                                                                       'payloads': ['wifi.ps1']}}},
                                                                     'tactic': 'discovery',
                                                                     'technique': {'attack_id': 'T1016',
                                                                                   'name': 'System '
                                                                                           'Network '
                                                                                           'Configuration '
                                                                                           'Discovery'}}},
 {'Mitre Stockpile - Ping the network in order to build the ARP cache': {'description': 'Ping '
                                                                                        'the '
                                                                                        'network '
                                                                                        'in '
                                                                                        'order '
                                                                                        'to '
                                                                                        'build '
                                                                                        'the '
                                                                                        'ARP '
                                                                                        'cache',
                                                                         'id': 'ac9dce33-2acc-4b34-94ce-2596409ce8f0',
                                                                         'name': 'Ping '
                                                                                 'network',
                                                                         'platforms': {'darwin': {'sh': {'command': 'for '
                                                                                                                    'ip '
                                                                                                                    'in '
                                                                                                                    '$(seq '
                                                                                                                    '190 '
                                                                                                                    '199); '
                                                                                                                    'do '
                                                                                                                    'ping '
                                                                                                                    '-c '
                                                                                                                    '1 '
                                                                                                                    '$(echo '
                                                                                                                    '#{domain.broadcast.ip} '
                                                                                                                    '|\n'
                                                                                                                    'cut '
                                                                                                                    '-d. '
                                                                                                                    '-f-3).$ip '
                                                                                                                    '-W '
                                                                                                                    '1; '
                                                                                                                    'done\n'}}},
                                                                         'tactic': 'discovery',
                                                                         'technique': {'attack_id': 'T1016',
                                                                                       'name': 'System '
                                                                                               'Network '
                                                                                               'Configuration '
                                                                                               'Discovery'}}},
 {'Mitre Stockpile - Capture the local network broadcast IP address': {'description': 'Capture '
                                                                                      'the '
                                                                                      'local '
                                                                                      'network '
                                                                                      'broadcast '
                                                                                      'IP '
                                                                                      'address',
                                                                       'id': 'b6f545ef-f802-4537-b59d-2cb19831c8ed',
                                                                       'name': 'Snag '
                                                                               'broadcast '
                                                                               'IP',
                                                                       'platforms': {'darwin': {'sh': {'command': 'ifconfig '
                                                                                                                  '| '
                                                                                                                  'grep '
                                                                                                                  'broadcast'}}},
                                                                       'tactic': 'discovery',
                                                                       'technique': {'attack_id': 'T1016',
                                                                                     'name': 'System '
                                                                                             'Network '
                                                                                             'Configuration '
                                                                                             'Discovery'}}},
 {'Mitre Stockpile - View network configuration info for host': {'description': 'View '
                                                                                'network '
                                                                                'configuration '
                                                                                'info '
                                                                                'for '
                                                                                'host',
                                                                 'id': 'e8017c46-acb8-400c-a4b5-b3362b5b5baa',
                                                                 'name': 'Network '
                                                                         'Interface '
                                                                         'Configuration',
                                                                 'platforms': {'darwin': {'sh': {'command': 'sudo '
                                                                                                            'ifconfig\n'}},
                                                                               'linux': {'sh': {'command': 'sudo '
                                                                                                           'ifconfig\n'}},
                                                                               'windows': {'psh': {'command': 'ipconfig\n'}}},
                                                                 'tactic': 'discovery',
                                                                 'technique': {'attack_id': 'T1016',
                                                                               'name': 'System '
                                                                                       'Network '
                                                                                       'Configuration '
                                                                                       'Discovery'}}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1016',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/host/dnsserver":  '
                                                                                 '["T1016"],',
                                            'Empire Module': 'powershell/situational_awareness/host/dnsserver',
                                            'Technique': 'System Network '
                                                         'Configuration '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1016',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/host/get_proxy":  '
                                                                                 '["T1016"],',
                                            'Empire Module': 'powershell/situational_awareness/host/get_proxy',
                                            'Technique': 'System Network '
                                                         'Configuration '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1016',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/arpscan":  '
                                                                                 '["T1016"],',
                                            'Empire Module': 'powershell/situational_awareness/network/arpscan',
                                            'Technique': 'System Network '
                                                         'Configuration '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1016',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_subnet":  '
                                                                                 '["T1016"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_subnet',
                                            'Technique': 'System Network '
                                                         'Configuration '
                                                         'Discovery'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations


* [System Network Configuration Discovery Mitigation](../mitigations/System-Network-Configuration-Discovery-Mitigation.md)


# Actors


* [APT19](../actors/APT19.md)

* [APT3](../actors/APT3.md)
    
* [menuPass](../actors/menuPass.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [Darkhotel](../actors/Darkhotel.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [Turla](../actors/Turla.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [admin@338](../actors/admin@338.md)
    
* [APT32](../actors/APT32.md)
    
* [Stealth Falcon](../actors/Stealth-Falcon.md)
    
* [APT1](../actors/APT1.md)
    
* [Naikon](../actors/Naikon.md)
    
* [MuddyWater](../actors/MuddyWater.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [APT41](../actors/APT41.md)
    
* [Frankenstein](../actors/Frankenstein.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
