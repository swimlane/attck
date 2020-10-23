
# Remote System Discovery

## Description

### MITRE Description

> Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system. Functionality could exist within remote access tools to enable this, but utilities available on the operating system could also be used such as  [Ping](https://attack.mitre.org/software/S0097) or <code>net view</code> using [Net](https://attack.mitre.org/software/S0039). Adversaries may also use local host files (ex: <code>C:\Windows\System32\Drivers\etc\hosts</code> or <code>/etc/hosts</code>) in order to discover the hostname to IP address mappings of remote systems. 

Specific to macOS, the <code>bonjour</code> protocol exists to discover additional Mac-based systems within the same broadcast domain.

Within IaaS (Infrastructure as a Service) environments, remote systems include instances and virtual machines in various states, including the running or stopped state. Cloud providers have created methods to serve information about remote systems, such as APIs and CLIs. For example, AWS provides a <code>DescribeInstances</code> API within the Amazon EC2 API and a <code>describe-instances</code> command within the AWS CLI that can return information about all instances within an account.(Citation: Amazon Describe Instances API)(Citation: Amazon Describe Instances CLI) Similarly, GCP's Cloud SDK CLI provides the <code>gcloud compute instances list</code> command to list all Google Compute Engine instances in a project, and Azure's CLI <code>az vm list</code> lists details of virtual machines.(Citation: Google Compute Instances)(Citation: Azure VM List)

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM']
* Platforms: ['Linux', 'macOS', 'Windows', 'GCP', 'Azure', 'AWS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1018

## Potential Commands

```
net group "Domain Computers" /domain[:DOMAIN]
net group "Domain Computers" /domain

post/windows/gather/enum_ad_computers
post/windows/gather/enum_computers
net group "Domain Controllers" /domain[:DOMAIN]
net group "Domain Controllers" /domain
nltest /dclist[:domain]
echo %LOGONSERVER%
shell echo %LOGONSERVER%
net view /domain
net view

net group "Domain Computers" /domain

nltest.exe /dclist:domain.local

for /l %i in (1,1,254) do ping -n 1 -w 100 192.168.1.%i

arp -a

arp -a | grep -v '^?'

for ip in $(seq 1 #{stop_host}); do ping -c 1 #{subnet}.$ip; [ $? -eq 0 ] && echo "#{subnet}.$ip UP" || : ; done

for ip in $(seq #{start_host} 254); do ping -c 1 #{subnet}.$ip; [ $? -eq 0 ] && echo "#{subnet}.$ip UP" || : ; done

for ip in $(seq #{start_host} #{stop_host}); do ping -c 1 192.168.1.$ip; [ $? -eq 0 ] && echo "192.168.1.$ip UP" || : ; done

$localip = ((ipconfig | findstr [0-9].\.)[0]).Split()[-1]
$pieces = $localip.split(".")
$firstOctet = $pieces[0]
$secondOctet = $pieces[1]
$thirdOctet = $pieces[2]
foreach ($ip in 1..255 | % { "$firstOctet.$secondOctet.$thirdOctet.$_" } ) {cmd.exe /c nslookup $ip}

adidnsdump -u domain\user -p #{acct_pass} --print-zones #{host_name}

adidnsdump -u #{user_name} -p password --print-zones #{host_name}

adidnsdump -u #{user_name} -p #{acct_pass} --print-zones 192.168.1.1

{'windows': {'psh': {'command': 'Import-Module .\\PowerView.ps1 -Force;\nGet-NetComputer\n', 'payloads': ['powerview.ps1']}}}
{'windows': {'psh': {'command': 'Import-Module .\\powerview.ps1;\nGet-DomainComputer\n', 'parsers': {'plugins.stockpile.app.parsers.gdomain': [{'source': 'remote.host.fqdn'}]}, 'payloads': ['powerview.ps1']}}}
{'windows': {'cmd': {'command': 'nltest /dsgetdc:%USERDOMAIN%\n'}, 'psh': {'command': 'nltest /dsgetdc:$env:USERDOMAIN\n'}}}
{'darwin': {'sh': {'command': 'cat ~/.ssh/known_hosts\n'}}, 'linux': {'sh': {'command': 'cat ~/.ssh/known_hosts\n'}}}
{'darwin': {'sh': {'command': 'arp -a', 'parsers': {'plugins.stockpile.app.parsers.ipaddr': [{'source': 'remote.host.ip'}]}}}, 'linux': {'sh': {'command': 'arp -a', 'parsers': {'plugins.stockpile.app.parsers.ipaddr': [{'source': 'remote.host.ip'}]}}}, 'windows': {'psh,cmd': {'command': 'arp -a', 'parsers': {'plugins.stockpile.app.parsers.ipaddr': [{'source': 'remote.host.ip'}]}}}}
{'windows': {'cmd': {'command': 'nltest /dsgetdc:%USERDOMAIN%\n'}, 'psh': {'command': 'nltest /dsgetdc:$env:USERDOMAIN\n'}}}
{'linux': {'sh': {'command': 'host "#{target.org.domain}" | grep mail | grep -oE \'[^ ]+$\' | rev | cut -c 2- | rev', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'target.org.emailhost'}]}}}, 'darwin': {'sh': {'command': 'host "#{target.org.domain}" | grep mail | grep -oE \'[^ ]+$\' | rev | cut -c 2- | rev', 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'target.org.emailhost'}]}}}, 'windows': {'psh': {'command': "(nslookup -querytype=mx #{target.org.domain}. | Select-String -pattern 'mail' | Out-String).Trim()\n", 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'target.org.emailhost'}]}}}}
{'windows': {'psh': {'command': 'nslookup #{remote.host.ip}\n', 'parsers': {'plugins.stockpile.app.parsers.reverse_nslookup': [{'source': 'remote.host.fqdn', 'edge': 'has_ip', 'target': 'remote.host.ip'}]}}}}
{'windows': {'psh': {'command': 'nbtstat -A #{remote.host.ip}'}}}
net.exe view /domain
qwinsta.exe /server:
installutil.exe /logfile= /LogToConsole=false /U *.dll
powershell/situational_awareness/network/powerview/get_domain_controller
powershell/situational_awareness/network/powerview/get_domain_controller
powershell/situational_awareness/network/powerview/get_domain_policy
powershell/situational_awareness/network/powerview/get_domain_policy
powershell/situational_awareness/network/powerview/get_domain_trust
powershell/situational_awareness/network/powerview/get_domain_trust
powershell/situational_awareness/network/powerview/get_forest
powershell/situational_awareness/network/powerview/get_forest
powershell/situational_awareness/network/powerview/get_forest_domain
powershell/situational_awareness/network/powerview/get_forest_domain
powershell/situational_awareness/network/powerview/get_site
powershell/situational_awareness/network/powerview/get_site
powershell/situational_awareness/network/reverse_dns
powershell/situational_awareness/network/reverse_dns
python/situational_awareness/network/active_directory/get_computers
python/situational_awareness/network/active_directory/get_computers
python/situational_awareness/network/active_directory/get_domaincontrollers
python/situational_awareness/network/active_directory/get_domaincontrollers
python/situational_awareness/network/gethostbyname
python/situational_awareness/network/gethostbyname
```

## Commands Dataset

```
[{'command': 'net group "Domain Computers" /domain[:DOMAIN]',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'net group "Domain Computers" /domain',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': '\n'
             'post/windows/gather/enum_ad_computers\n'
             'post/windows/gather/enum_computers',
  'name': 'Metasploit',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'net group "Domain Controllers" /domain[:DOMAIN]',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'net group "Domain Controllers" /domain',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'nltest /dclist[:domain]',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'echo %LOGONSERVER%',
  'name': 'Built-in Windows Command',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'shell echo %LOGONSERVER%',
  'name': 'Cobalt Strike',
  'source': 'https://attack.mitre.org/docs/APT3_Adversary_Emulation_Field_Manual.xlsx'},
 {'command': 'net view /domain\nnet view\n',
  'name': None,
  'source': 'atomics/T1018/T1018.yaml'},
 {'command': 'net group "Domain Computers" /domain\n',
  'name': None,
  'source': 'atomics/T1018/T1018.yaml'},
 {'command': 'nltest.exe /dclist:domain.local\n',
  'name': None,
  'source': 'atomics/T1018/T1018.yaml'},
 {'command': 'for /l %i in (1,1,254) do ping -n 1 -w 100 192.168.1.%i\n',
  'name': None,
  'source': 'atomics/T1018/T1018.yaml'},
 {'command': 'arp -a\n', 'name': None, 'source': 'atomics/T1018/T1018.yaml'},
 {'command': "arp -a | grep -v '^?'\n",
  'name': None,
  'source': 'atomics/T1018/T1018.yaml'},
 {'command': 'for ip in $(seq 1 #{stop_host}); do ping -c 1 #{subnet}.$ip; [ '
             '$? -eq 0 ] && echo "#{subnet}.$ip UP" || : ; done\n',
  'name': None,
  'source': 'atomics/T1018/T1018.yaml'},
 {'command': 'for ip in $(seq #{start_host} 254); do ping -c 1 #{subnet}.$ip; '
             '[ $? -eq 0 ] && echo "#{subnet}.$ip UP" || : ; done\n',
  'name': None,
  'source': 'atomics/T1018/T1018.yaml'},
 {'command': 'for ip in $(seq #{start_host} #{stop_host}); do ping -c 1 '
             '192.168.1.$ip; [ $? -eq 0 ] && echo "192.168.1.$ip UP" || : ; '
             'done\n',
  'name': None,
  'source': 'atomics/T1018/T1018.yaml'},
 {'command': '$localip = ((ipconfig | findstr [0-9].\\.)[0]).Split()[-1]\n'
             '$pieces = $localip.split(".")\n'
             '$firstOctet = $pieces[0]\n'
             '$secondOctet = $pieces[1]\n'
             '$thirdOctet = $pieces[2]\n'
             'foreach ($ip in 1..255 | % { '
             '"$firstOctet.$secondOctet.$thirdOctet.$_" } ) {cmd.exe /c '
             'nslookup $ip}\n',
  'name': None,
  'source': 'atomics/T1018/T1018.yaml'},
 {'command': 'adidnsdump -u domain\\user -p #{acct_pass} --print-zones '
             '#{host_name}\n',
  'name': None,
  'source': 'atomics/T1018/T1018.yaml'},
 {'command': 'adidnsdump -u #{user_name} -p password --print-zones '
             '#{host_name}\n',
  'name': None,
  'source': 'atomics/T1018/T1018.yaml'},
 {'command': 'adidnsdump -u #{user_name} -p #{acct_pass} --print-zones '
             '192.168.1.1\n',
  'name': None,
  'source': 'atomics/T1018/T1018.yaml'},
 {'command': {'windows': {'psh': {'command': 'Import-Module .\\PowerView.ps1 '
                                             '-Force;\n'
                                             'Get-NetComputer\n',
                                  'payloads': ['powerview.ps1']}}},
  'name': 'Get a list of all computers in a domain',
  'source': 'data/abilities/discovery/0360ede1-3c28-48d3-a6ef-6e98f562c5af.yml'},
 {'command': {'windows': {'psh': {'command': 'Import-Module .\\powerview.ps1;\n'
                                             'Get-DomainComputer\n',
                                  'parsers': {'plugins.stockpile.app.parsers.gdomain': [{'source': 'remote.host.fqdn'}]},
                                  'payloads': ['powerview.ps1']}}},
  'name': 'Use PowerView to query the Active Directory server for a list of '
          'computers in the Domain',
  'source': 'data/abilities/discovery/13379ae1-d20e-4162-91f8-320d78a35e7f.yml'},
 {'command': {'windows': {'cmd': {'command': 'nltest /dsgetdc:%USERDOMAIN%\n'},
                          'psh': {'command': 'nltest '
                                             '/dsgetdc:$env:USERDOMAIN\n'}}},
  'name': 'Identify the remote domain controllers',
  'source': 'data/abilities/discovery/26c8b8b5-7b5b-4de1-a128-7d37fb14f517.yml'},
 {'command': {'darwin': {'sh': {'command': 'cat ~/.ssh/known_hosts\n'}},
              'linux': {'sh': {'command': 'cat ~/.ssh/known_hosts\n'}}},
  'name': 'View the known_hosts file',
  'source': 'data/abilities/discovery/5f77ecf9-613f-4863-8d2f-ed6b447a4633.yml'},
 {'command': {'darwin': {'sh': {'command': 'arp -a',
                                'parsers': {'plugins.stockpile.app.parsers.ipaddr': [{'source': 'remote.host.ip'}]}}},
              'linux': {'sh': {'command': 'arp -a',
                               'parsers': {'plugins.stockpile.app.parsers.ipaddr': [{'source': 'remote.host.ip'}]}}},
              'windows': {'psh,cmd': {'command': 'arp -a',
                                      'parsers': {'plugins.stockpile.app.parsers.ipaddr': [{'source': 'remote.host.ip'}]}}}},
  'name': 'Locate all active IP and FQDNs on the network',
  'source': 'data/abilities/discovery/85341c8c-4ecb-4579-8f53-43e3e91d7617.yml'},
 {'command': {'windows': {'cmd': {'command': 'nltest /dsgetdc:%USERDOMAIN%\n'},
                          'psh': {'command': 'nltest '
                                             '/dsgetdc:$env:USERDOMAIN\n'}}},
  'name': 'Identify remote domain controller',
  'source': 'data/abilities/discovery/b22b3b47-6219-4504-a2e6-ae8263e49fc3.yml'},
 {'command': {'darwin': {'sh': {'command': 'host "#{target.org.domain}" | grep '
                                           "mail | grep -oE '[^ ]+$' | rev | "
                                           'cut -c 2- | rev',
                                'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'target.org.emailhost'}]}}},
              'linux': {'sh': {'command': 'host "#{target.org.domain}" | grep '
                                          "mail | grep -oE '[^ ]+$' | rev | "
                                          'cut -c 2- | rev',
                               'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'target.org.emailhost'}]}}},
              'windows': {'psh': {'command': '(nslookup -querytype=mx '
                                             '#{target.org.domain}. | '
                                             "Select-String -pattern 'mail' | "
                                             'Out-String).Trim()\n',
                                  'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'target.org.emailhost'}]}}}},
  'name': 'Identify the organizations mail server',
  'source': 'data/abilities/discovery/ce485320-41a4-42e8-a510-f5a8fe96a644.yml'},
 {'command': {'windows': {'psh': {'command': 'nslookup #{remote.host.ip}\n',
                                  'parsers': {'plugins.stockpile.app.parsers.reverse_nslookup': [{'edge': 'has_ip',
                                                                                                  'source': 'remote.host.fqdn',
                                                                                                  'target': 'remote.host.ip'}]}}}},
  'name': 'Find hostname of remote IP in domain',
  'source': 'data/abilities/discovery/fa4ed735-7006-4451-a578-b516f80e559f.yml'},
 {'command': {'windows': {'psh': {'command': 'nbtstat -A #{remote.host.ip}'}}},
  'name': 'Find hostname of remote host',
  'source': 'data/abilities/discovery/fdf8bf36-797f-4157-805b-fe7c1c6fc903.yml'},
 {'command': 'net.exe view /domain',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'qwinsta.exe /server:',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'installutil.exe /logfile= /LogToConsole=false /U *.dll',
  'name': None,
  'source': 'Threat Hunting Tables'},
 {'command': 'powershell/situational_awareness/network/powerview/get_domain_controller',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_domain_controller',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_domain_policy',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_domain_policy',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_domain_trust',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_domain_trust',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_forest',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_forest',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_forest_domain',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_forest_domain',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_site',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/powerview/get_site',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/reverse_dns',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/situational_awareness/network/reverse_dns',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/get_computers',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/get_computers',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/get_domaincontrollers',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/active_directory/get_domaincontrollers',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/gethostbyname',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'python/situational_awareness/network/gethostbyname',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['5156', 'Win Firewall']},
 {'data_source': ['Network protocol analysis']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['4688 ', 'Process CMD Line']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['Network protocol analysis']}]
```

## Potential Queries

```json
[{'name': 'Remote System Discovery Network',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where EventID == 3 and (process_path contains "net.exe"or '
           'process_path contains "ping.exe")and (process_command_line '
           'contains "view"or process_command_line contains "ping")'},
 {'name': 'Remote System Discovery Process',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (process_path contains "net.exe"or process_path '
           'contains "ping.exe")and (process_command_line contains "view"or '
           'process_command_line contains "ping")'}]
```

## Raw Dataset

```json
[{'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'net '
                                                                              'group '
                                                                              '"Domain '
                                                                              'Computers" '
                                                                              '/domain[:DOMAIN]',
                                                  'Category': 'T1018',
                                                  'Cobalt Strike': 'net group '
                                                                   '"Domain '
                                                                   'Computers" '
                                                                   '/domain',
                                                  'Description': 'Display the '
                                                                 'list of '
                                                                 'domain '
                                                                 'computers in '
                                                                 'the domain '
                                                                 'by showing '
                                                                 'their '
                                                                 'computer '
                                                                 'accounts '
                                                                 '(COMP_NAME$)',
                                                  'Metasploit': '\n'
                                                                'post/windows/gather/enum_ad_computers\n'
                                                                'post/windows/gather/enum_computers'}},
 {'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'net '
                                                                              'group '
                                                                              '"Domain '
                                                                              'Controllers" '
                                                                              '/domain[:DOMAIN]',
                                                  'Category': 'T1018',
                                                  'Cobalt Strike': 'net group '
                                                                   '"Domain '
                                                                   'Controllers" '
                                                                   '/domain',
                                                  'Description': 'Display the '
                                                                 'list of '
                                                                 'domain '
                                                                 'controllers '
                                                                 'in the '
                                                                 'network',
                                                  'Metasploit': ''}},
 {'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'nltest '
                                                                              '/dclist[:domain]',
                                                  'Category': 'T1018',
                                                  'Cobalt Strike': '',
                                                  'Description': 'Display the '
                                                                 'trust '
                                                                 'relationship '
                                                                 'between the '
                                                                 'workstation '
                                                                 'and the '
                                                                 'domain - '
                                                                 'must be '
                                                                 'elevated to '
                                                                 'use this!',
                                                  'Metasploit': ''}},
 {'Mitre APT3 Adversary Emulation Field Manual': {'Built-in Windows Command': 'echo '
                                                                              '%LOGONSERVER%',
                                                  'Category': 'T1018',
                                                  'Cobalt Strike': 'shell echo '
                                                                   '%LOGONSERVER%',
                                                  'Description': 'Display the '
                                                                 'active '
                                                                 'directory '
                                                                 'login server '
                                                                 'of the '
                                                                 'workstation ',
                                                  'Metasploit': ''}},
 {'Atomic Red Team Test - Remote System Discovery': {'atomic_tests': [{'auto_generated_guid': '85321a9c-897f-4a60-9f20-29788e50bccd',
                                                                       'description': 'Identify '
                                                                                      'remote '
                                                                                      'systems '
                                                                                      'with '
                                                                                      'net.exe.\n'
                                                                                      '\n'
                                                                                      'Upon '
                                                                                      'successful '
                                                                                      'execution, '
                                                                                      'cmd.exe '
                                                                                      'will '
                                                                                      'execute '
                                                                                      '`net.exe '
                                                                                      'view` '
                                                                                      'and '
                                                                                      'display '
                                                                                      'results '
                                                                                      'of '
                                                                                      'local '
                                                                                      'systems '
                                                                                      'on '
                                                                                      'the '
                                                                                      'network '
                                                                                      'that '
                                                                                      'have '
                                                                                      'file '
                                                                                      'and '
                                                                                      'print '
                                                                                      'sharing '
                                                                                      'enabled.\n',
                                                                       'executor': {'command': 'net '
                                                                                               'view '
                                                                                               '/domain\n'
                                                                                               'net '
                                                                                               'view\n',
                                                                                    'name': 'command_prompt'},
                                                                       'name': 'Remote '
                                                                               'System '
                                                                               'Discovery '
                                                                               '- '
                                                                               'net',
                                                                       'supported_platforms': ['windows']},
                                                                      {'auto_generated_guid': 'f1bf6c8f-9016-4edf-aff9-80b65f5d711f',
                                                                       'description': 'Identify '
                                                                                      'remote '
                                                                                      'systems '
                                                                                      'with '
                                                                                      'net.exe '
                                                                                      'querying '
                                                                                      'the '
                                                                                      'Active '
                                                                                      'Directory '
                                                                                      'Domain '
                                                                                      'Computers '
                                                                                      'group.\n'
                                                                                      '\n'
                                                                                      'Upon '
                                                                                      'successful '
                                                                                      'execution, '
                                                                                      'cmd.exe '
                                                                                      'will '
                                                                                      'execute '
                                                                                      'cmd.exe '
                                                                                      'against '
                                                                                      'Active '
                                                                                      'Directory '
                                                                                      'to '
                                                                                      'list '
                                                                                      'the '
                                                                                      '"Domain '
                                                                                      'Computers" '
                                                                                      'group. '
                                                                                      'Output '
                                                                                      'will '
                                                                                      'be '
                                                                                      'via '
                                                                                      'stdout.\n',
                                                                       'executor': {'command': 'net '
                                                                                               'group '
                                                                                               '"Domain '
                                                                                               'Computers" '
                                                                                               '/domain\n',
                                                                                    'name': 'command_prompt'},
                                                                       'name': 'Remote '
                                                                               'System '
                                                                               'Discovery '
                                                                               '- '
                                                                               'net '
                                                                               'group '
                                                                               'Domain '
                                                                               'Computers',
                                                                       'supported_platforms': ['windows']},
                                                                      {'auto_generated_guid': '52ab5108-3f6f-42fb-8ba3-73bc054f22c8',
                                                                       'description': 'Identify '
                                                                                      'domain '
                                                                                      'controllers '
                                                                                      'for '
                                                                                      'specified '
                                                                                      'domain.\n'
                                                                                      '\n'
                                                                                      'Upon '
                                                                                      'successful '
                                                                                      'execution, '
                                                                                      'cmd.exe '
                                                                                      'will '
                                                                                      'execute '
                                                                                      'nltest.exe '
                                                                                      'against '
                                                                                      'a '
                                                                                      'target '
                                                                                      'domain '
                                                                                      'to '
                                                                                      'retrieve '
                                                                                      'a '
                                                                                      'list '
                                                                                      'of '
                                                                                      'domain '
                                                                                      'controllers. '
                                                                                      'Output '
                                                                                      'will '
                                                                                      'be '
                                                                                      'via '
                                                                                      'stdout.\n',
                                                                       'executor': {'command': 'nltest.exe '
                                                                                               '/dclist:#{target_domain}\n',
                                                                                    'name': 'command_prompt'},
                                                                       'input_arguments': {'target_domain': {'default': 'domain.local',
                                                                                                             'description': 'Domain '
                                                                                                                            'to '
                                                                                                                            'query '
                                                                                                                            'for '
                                                                                                                            'domain '
                                                                                                                            'controllers',
                                                                                                             'type': 'String'}},
                                                                       'name': 'Remote '
                                                                               'System '
                                                                               'Discovery '
                                                                               '- '
                                                                               'nltest',
                                                                       'supported_platforms': ['windows']},
                                                                      {'auto_generated_guid': '6db1f57f-d1d5-4223-8a66-55c9c65a9592',
                                                                       'description': 'Identify '
                                                                                      'remote '
                                                                                      'systems '
                                                                                      'via '
                                                                                      'ping '
                                                                                      'sweep.\n'
                                                                                      '\n'
                                                                                      'Upon '
                                                                                      'successful '
                                                                                      'execution, '
                                                                                      'cmd.exe '
                                                                                      'will '
                                                                                      'perform '
                                                                                      'a '
                                                                                      'for '
                                                                                      'loop '
                                                                                      'against '
                                                                                      'the '
                                                                                      '192.168.1.1/24 '
                                                                                      'network. '
                                                                                      'Output '
                                                                                      'will '
                                                                                      'be '
                                                                                      'via '
                                                                                      'stdout.\n',
                                                                       'executor': {'command': 'for '
                                                                                               '/l '
                                                                                               '%i '
                                                                                               'in '
                                                                                               '(1,1,254) '
                                                                                               'do '
                                                                                               'ping '
                                                                                               '-n '
                                                                                               '1 '
                                                                                               '-w '
                                                                                               '100 '
                                                                                               '192.168.1.%i\n',
                                                                                    'name': 'command_prompt'},
                                                                       'name': 'Remote '
                                                                               'System '
                                                                               'Discovery '
                                                                               '- '
                                                                               'ping '
                                                                               'sweep',
                                                                       'supported_platforms': ['windows']},
                                                                      {'auto_generated_guid': '2d5a61f5-0447-4be4-944a-1f8530ed6574',
                                                                       'description': 'Identify '
                                                                                      'remote '
                                                                                      'systems '
                                                                                      'via '
                                                                                      'arp. \n'
                                                                                      '\n'
                                                                                      'Upon '
                                                                                      'successful '
                                                                                      'execution, '
                                                                                      'cmd.exe '
                                                                                      'will '
                                                                                      'execute '
                                                                                      'arp '
                                                                                      'to '
                                                                                      'list '
                                                                                      'out '
                                                                                      'the '
                                                                                      'arp '
                                                                                      'cache. '
                                                                                      'Output '
                                                                                      'will '
                                                                                      'be '
                                                                                      'via '
                                                                                      'stdout.\n',
                                                                       'executor': {'command': 'arp '
                                                                                               '-a\n',
                                                                                    'name': 'command_prompt'},
                                                                       'name': 'Remote '
                                                                               'System '
                                                                               'Discovery '
                                                                               '- '
                                                                               'arp',
                                                                       'supported_platforms': ['windows']},
                                                                      {'auto_generated_guid': 'acb6b1ff-e2ad-4d64-806c-6c35fe73b951',
                                                                       'dependencies': [{'description': 'Check '
                                                                                                        'if '
                                                                                                        'arp '
                                                                                                        'command '
                                                                                                        'exists '
                                                                                                        'on '
                                                                                                        'the '
                                                                                                        'machine\n',
                                                                                         'get_prereq_command': 'echo '
                                                                                                               '"Install '
                                                                                                               'arp '
                                                                                                               'on '
                                                                                                               'the '
                                                                                                               'machine."; '
                                                                                                               'exit '
                                                                                                               '1;\n',
                                                                                         'prereq_command': 'if '
                                                                                                           '[ '
                                                                                                           '-x '
                                                                                                           '"$(command '
                                                                                                           '-v '
                                                                                                           'arp)" '
                                                                                                           ']; '
                                                                                                           'then '
                                                                                                           'exit '
                                                                                                           '0; '
                                                                                                           'else '
                                                                                                           'exit '
                                                                                                           '1; '
                                                                                                           'fi;\n'}],
                                                                       'dependency_executor_name': 'sh',
                                                                       'description': 'Identify '
                                                                                      'remote '
                                                                                      'systems '
                                                                                      'via '
                                                                                      'arp.\n'
                                                                                      '\n'
                                                                                      'Upon '
                                                                                      'successful '
                                                                                      'execution, '
                                                                                      'sh '
                                                                                      'will '
                                                                                      'execute '
                                                                                      'arp '
                                                                                      'to '
                                                                                      'list '
                                                                                      'out '
                                                                                      'the '
                                                                                      'arp '
                                                                                      'cache. '
                                                                                      'Output '
                                                                                      'will '
                                                                                      'be '
                                                                                      'via '
                                                                                      'stdout.\n',
                                                                       'executor': {'command': 'arp '
                                                                                               '-a '
                                                                                               '| '
                                                                                               'grep '
                                                                                               '-v '
                                                                                               "'^?'\n",
                                                                                    'name': 'sh'},
                                                                       'name': 'Remote '
                                                                               'System '
                                                                               'Discovery '
                                                                               '- '
                                                                               'arp '
                                                                               'nix',
                                                                       'supported_platforms': ['linux',
                                                                                               'macos']},
                                                                      {'auto_generated_guid': '96db2632-8417-4dbb-b8bb-a8b92ba391de',
                                                                       'description': 'Identify '
                                                                                      'remote '
                                                                                      'systems '
                                                                                      'via '
                                                                                      'ping '
                                                                                      'sweep.\n'
                                                                                      '\n'
                                                                                      'Upon '
                                                                                      'successful '
                                                                                      'execution, '
                                                                                      'sh '
                                                                                      'will '
                                                                                      'perform '
                                                                                      'a '
                                                                                      'ping '
                                                                                      'sweep '
                                                                                      'on '
                                                                                      'the '
                                                                                      '192.168.1.1/24 '
                                                                                      'and '
                                                                                      'echo '
                                                                                      'via '
                                                                                      'stdout '
                                                                                      'if '
                                                                                      'an '
                                                                                      'IP '
                                                                                      'is '
                                                                                      'active.\n',
                                                                       'executor': {'command': 'for '
                                                                                               'ip '
                                                                                               'in '
                                                                                               '$(seq '
                                                                                               '#{start_host} '
                                                                                               '#{stop_host}); '
                                                                                               'do '
                                                                                               'ping '
                                                                                               '-c '
                                                                                               '1 '
                                                                                               '#{subnet}.$ip; '
                                                                                               '[ '
                                                                                               '$? '
                                                                                               '-eq '
                                                                                               '0 '
                                                                                               '] '
                                                                                               '&& '
                                                                                               'echo '
                                                                                               '"#{subnet}.$ip '
                                                                                               'UP" '
                                                                                               '|| '
                                                                                               ': '
                                                                                               '; '
                                                                                               'done\n',
                                                                                    'name': 'sh'},
                                                                       'input_arguments': {'start_host': {'default': '1',
                                                                                                          'description': 'Subnet '
                                                                                                                         'used '
                                                                                                                         'for '
                                                                                                                         'ping '
                                                                                                                         'sweep.',
                                                                                                          'type': 'string'},
                                                                                           'stop_host': {'default': '254',
                                                                                                         'description': 'Subnet '
                                                                                                                        'used '
                                                                                                                        'for '
                                                                                                                        'ping '
                                                                                                                        'sweep.',
                                                                                                         'type': 'string'},
                                                                                           'subnet': {'default': '192.168.1',
                                                                                                      'description': 'Subnet '
                                                                                                                     'used '
                                                                                                                     'for '
                                                                                                                     'ping '
                                                                                                                     'sweep.',
                                                                                                      'type': 'string'}},
                                                                       'name': 'Remote '
                                                                               'System '
                                                                               'Discovery '
                                                                               '- '
                                                                               'sweep',
                                                                       'supported_platforms': ['linux',
                                                                                               'macos']},
                                                                      {'auto_generated_guid': 'baa01aaa-5e13-45ec-8a0d-e46c93c9760f',
                                                                       'description': 'Powershell '
                                                                                      'script '
                                                                                      'that '
                                                                                      'runs '
                                                                                      'nslookup '
                                                                                      'on '
                                                                                      'cmd.exe '
                                                                                      'against '
                                                                                      'the '
                                                                                      'local '
                                                                                      '/24 '
                                                                                      'network '
                                                                                      'of '
                                                                                      'the '
                                                                                      'first '
                                                                                      'network '
                                                                                      'adaptor '
                                                                                      'listed '
                                                                                      'in '
                                                                                      'ipconfig.\n'
                                                                                      '\n'
                                                                                      'Upon '
                                                                                      'successful '
                                                                                      'execution, '
                                                                                      'powershell '
                                                                                      'will '
                                                                                      'identify '
                                                                                      'the '
                                                                                      'ip '
                                                                                      'range '
                                                                                      '(via '
                                                                                      'ipconfig) '
                                                                                      'and '
                                                                                      'perform '
                                                                                      'a '
                                                                                      'for '
                                                                                      'loop '
                                                                                      'and '
                                                                                      'execute '
                                                                                      'nslookup '
                                                                                      'against '
                                                                                      'that '
                                                                                      'IP '
                                                                                      'range. '
                                                                                      'Output '
                                                                                      'will '
                                                                                      'be '
                                                                                      'via '
                                                                                      'stdout.\n',
                                                                       'executor': {'command': '$localip '
                                                                                               '= '
                                                                                               '((ipconfig '
                                                                                               '| '
                                                                                               'findstr '
                                                                                               '[0-9].\\.)[0]).Split()[-1]\n'
                                                                                               '$pieces '
                                                                                               '= '
                                                                                               '$localip.split(".")\n'
                                                                                               '$firstOctet '
                                                                                               '= '
                                                                                               '$pieces[0]\n'
                                                                                               '$secondOctet '
                                                                                               '= '
                                                                                               '$pieces[1]\n'
                                                                                               '$thirdOctet '
                                                                                               '= '
                                                                                               '$pieces[2]\n'
                                                                                               'foreach '
                                                                                               '($ip '
                                                                                               'in '
                                                                                               '1..255 '
                                                                                               '| '
                                                                                               '% '
                                                                                               '{ '
                                                                                               '"$firstOctet.$secondOctet.$thirdOctet.$_" '
                                                                                               '} '
                                                                                               ') '
                                                                                               '{cmd.exe '
                                                                                               '/c '
                                                                                               'nslookup '
                                                                                               '$ip}\n',
                                                                                    'elevation_required': True,
                                                                                    'name': 'powershell'},
                                                                       'name': 'Remote '
                                                                               'System '
                                                                               'Discovery '
                                                                               '- '
                                                                               'nslookup',
                                                                       'supported_platforms': ['windows']},
                                                                      {'auto_generated_guid': '95e19466-469e-4316-86d2-1dc401b5a959',
                                                                       'dependencies': [{'description': 'Computer '
                                                                                                        'must '
                                                                                                        'have '
                                                                                                        'python '
                                                                                                        '3 '
                                                                                                        'installed\n',
                                                                                         'get_prereq_command': 'echo '
                                                                                                               '"Python '
                                                                                                               '3 '
                                                                                                               'must '
                                                                                                               'be '
                                                                                                               'installed '
                                                                                                               'manually"\n',
                                                                                         'prereq_command': 'if '
                                                                                                           '(python '
                                                                                                           '--version) '
                                                                                                           '{exit '
                                                                                                           '0} '
                                                                                                           'else '
                                                                                                           '{exit '
                                                                                                           '1}\n'},
                                                                                        {'description': 'Computer '
                                                                                                        'must '
                                                                                                        'have '
                                                                                                        'pip '
                                                                                                        'installed\n',
                                                                                         'get_prereq_command': 'echo '
                                                                                                               '"PIP '
                                                                                                               'must '
                                                                                                               'be '
                                                                                                               'installed '
                                                                                                               'manually"\n',
                                                                                         'prereq_command': 'if '
                                                                                                           '(pip3 '
                                                                                                           '-V) '
                                                                                                           '{exit '
                                                                                                           '0} '
                                                                                                           'else '
                                                                                                           '{exit '
                                                                                                           '1}\n'},
                                                                                        {'description': 'adidnsdump '
                                                                                                        'must '
                                                                                                        'be '
                                                                                                        'installed '
                                                                                                        'and '
                                                                                                        'part '
                                                                                                        'of '
                                                                                                        'PATH\n',
                                                                                         'get_prereq_command': 'pip3 '
                                                                                                               'install '
                                                                                                               'adidnsdump\n',
                                                                                         'prereq_command': 'if '
                                                                                                           '(cmd '
                                                                                                           '/c '
                                                                                                           'adidnsdump '
                                                                                                           '-h) '
                                                                                                           '{exit '
                                                                                                           '0} '
                                                                                                           'else '
                                                                                                           '{exit '
                                                                                                           '1}\n'}],
                                                                       'dependency_executor_name': 'powershell',
                                                                       'description': 'This '
                                                                                      'tool '
                                                                                      'enables '
                                                                                      'enumeration '
                                                                                      'and '
                                                                                      'exporting '
                                                                                      'of '
                                                                                      'all '
                                                                                      'DNS '
                                                                                      'records '
                                                                                      'in '
                                                                                      'the '
                                                                                      'zone '
                                                                                      'for '
                                                                                      'recon '
                                                                                      'purposes '
                                                                                      'of '
                                                                                      'internal '
                                                                                      'networks\n'
                                                                                      'Python '
                                                                                      '3 '
                                                                                      'and '
                                                                                      'adidnsdump '
                                                                                      'must '
                                                                                      'be '
                                                                                      'installed, '
                                                                                      'use '
                                                                                      'the '
                                                                                      "get_prereq_command's "
                                                                                      'to '
                                                                                      'meet '
                                                                                      'the '
                                                                                      'prerequisites '
                                                                                      'for '
                                                                                      'this '
                                                                                      'test.\n'
                                                                                      'Successful '
                                                                                      'execution '
                                                                                      'of '
                                                                                      'this '
                                                                                      'test '
                                                                                      'will '
                                                                                      'list '
                                                                                      'dns '
                                                                                      'zones '
                                                                                      'in '
                                                                                      'the '
                                                                                      'terminal.\n',
                                                                       'executor': {'command': 'adidnsdump '
                                                                                               '-u '
                                                                                               '#{user_name} '
                                                                                               '-p '
                                                                                               '#{acct_pass} '
                                                                                               '--print-zones '
                                                                                               '#{host_name}\n',
                                                                                    'elevation_required': True,
                                                                                    'name': 'command_prompt'},
                                                                       'input_arguments': {'acct_pass': {'default': 'password',
                                                                                                         'description': 'Account '
                                                                                                                        'password.',
                                                                                                         'type': 'string'},
                                                                                           'host_name': {'default': '192.168.1.1',
                                                                                                         'description': 'hostname '
                                                                                                                        'or '
                                                                                                                        'ip '
                                                                                                                        'address '
                                                                                                                        'to '
                                                                                                                        'connect '
                                                                                                                        'to.',
                                                                                                         'type': 'string'},
                                                                                           'user_name': {'default': 'domain\\user',
                                                                                                         'description': 'username '
                                                                                                                        'including '
                                                                                                                        'domain.',
                                                                                                         'type': 'string'}},
                                                                       'name': 'Remote '
                                                                               'System '
                                                                               'Discovery '
                                                                               '- '
                                                                               'adidnsdump',
                                                                       'supported_platforms': ['windows']}],
                                                     'attack_technique': 'T1018',
                                                     'display_name': 'Remote '
                                                                     'System '
                                                                     'Discovery'}},
 {'Mitre Stockpile - Get a list of all computers in a domain': {'description': 'Get '
                                                                               'a '
                                                                               'list '
                                                                               'of '
                                                                               'all '
                                                                               'computers '
                                                                               'in '
                                                                               'a '
                                                                               'domain',
                                                                'id': '0360ede1-3c28-48d3-a6ef-6e98f562c5af',
                                                                'name': 'GetComputers '
                                                                        '(Alice)',
                                                                'platforms': {'windows': {'psh': {'command': 'Import-Module '
                                                                                                             '.\\PowerView.ps1 '
                                                                                                             '-Force;\n'
                                                                                                             'Get-NetComputer\n',
                                                                                                  'payloads': ['powerview.ps1']}}},
                                                                'tactic': 'discovery',
                                                                'technique': {'attack_id': 'T1018',
                                                                              'name': 'Remote '
                                                                                      'System '
                                                                                      'Discovery'}}},
 {'Mitre Stockpile - Use PowerView to query the Active Directory server for a list of computers in the Domain': {'description': 'Use '
                                                                                                                                'PowerView '
                                                                                                                                'to '
                                                                                                                                'query '
                                                                                                                                'the '
                                                                                                                                'Active '
                                                                                                                                'Directory '
                                                                                                                                'server '
                                                                                                                                'for '
                                                                                                                                'a '
                                                                                                                                'list '
                                                                                                                                'of '
                                                                                                                                'computers '
                                                                                                                                'in '
                                                                                                                                'the '
                                                                                                                                'Domain',
                                                                                                                 'id': '13379ae1-d20e-4162-91f8-320d78a35e7f',
                                                                                                                 'name': 'Discover '
                                                                                                                         'local '
                                                                                                                         'hosts',
                                                                                                                 'platforms': {'windows': {'psh': {'command': 'Import-Module '
                                                                                                                                                              '.\\powerview.ps1;\n'
                                                                                                                                                              'Get-DomainComputer\n',
                                                                                                                                                   'parsers': {'plugins.stockpile.app.parsers.gdomain': [{'source': 'remote.host.fqdn'}]},
                                                                                                                                                   'payloads': ['powerview.ps1']}}},
                                                                                                                 'tactic': 'discovery',
                                                                                                                 'technique': {'attack_id': 'T1018',
                                                                                                                               'name': 'Remote '
                                                                                                                                       'System '
                                                                                                                                       'Discovery'}}},
 {'Mitre Stockpile - Identify the remote domain controllers': {'description': 'Identify '
                                                                              'the '
                                                                              'remote '
                                                                              'domain '
                                                                              'controllers',
                                                               'id': '26c8b8b5-7b5b-4de1-a128-7d37fb14f517',
                                                               'name': 'Discover '
                                                                       'domain '
                                                                       'controller',
                                                               'platforms': {'windows': {'cmd': {'command': 'nltest '
                                                                                                            '/dsgetdc:%USERDOMAIN%\n'},
                                                                                         'psh': {'command': 'nltest '
                                                                                                            '/dsgetdc:$env:USERDOMAIN\n'}}},
                                                               'tactic': 'discovery',
                                                               'technique': {'attack_id': 'T1018',
                                                                             'name': 'Remote '
                                                                                     'System '
                                                                                     'Discovery'}}},
 {'Mitre Stockpile - View the known_hosts file': {'description': 'View the '
                                                                 'known_hosts '
                                                                 'file',
                                                  'id': '5f77ecf9-613f-4863-8d2f-ed6b447a4633',
                                                  'name': 'Parse SSH '
                                                          'known_hosts',
                                                  'platforms': {'darwin': {'sh': {'command': 'cat '
                                                                                             '~/.ssh/known_hosts\n'}},
                                                                'linux': {'sh': {'command': 'cat '
                                                                                            '~/.ssh/known_hosts\n'}}},
                                                  'tactic': 'discovery',
                                                  'technique': {'attack_id': 'T1018',
                                                                'name': 'Remote '
                                                                        'System '
                                                                        'Discovery'}}},
 {'Mitre Stockpile - Locate all active IP and FQDNs on the network': {'description': 'Locate '
                                                                                     'all '
                                                                                     'active '
                                                                                     'IP '
                                                                                     'and '
                                                                                     'FQDNs '
                                                                                     'on '
                                                                                     'the '
                                                                                     'network',
                                                                      'id': '85341c8c-4ecb-4579-8f53-43e3e91d7617',
                                                                      'name': 'Collect '
                                                                              'ARP '
                                                                              'details',
                                                                      'platforms': {'darwin': {'sh': {'command': 'arp '
                                                                                                                 '-a',
                                                                                                      'parsers': {'plugins.stockpile.app.parsers.ipaddr': [{'source': 'remote.host.ip'}]}}},
                                                                                    'linux': {'sh': {'command': 'arp '
                                                                                                                '-a',
                                                                                                     'parsers': {'plugins.stockpile.app.parsers.ipaddr': [{'source': 'remote.host.ip'}]}}},
                                                                                    'windows': {'psh,cmd': {'command': 'arp '
                                                                                                                       '-a',
                                                                                                            'parsers': {'plugins.stockpile.app.parsers.ipaddr': [{'source': 'remote.host.ip'}]}}}},
                                                                      'tactic': 'discovery',
                                                                      'technique': {'attack_id': 'T1018',
                                                                                    'name': 'Remote '
                                                                                            'System '
                                                                                            'Discovery'}}},
 {'Mitre Stockpile - Identify remote domain controller': {'description': 'Identify '
                                                                         'remote '
                                                                         'domain '
                                                                         'controller',
                                                          'id': 'b22b3b47-6219-4504-a2e6-ae8263e49fc3',
                                                          'name': 'Find domain '
                                                                  'controller',
                                                          'platforms': {'windows': {'cmd': {'command': 'nltest '
                                                                                                       '/dsgetdc:%USERDOMAIN%\n'},
                                                                                    'psh': {'command': 'nltest '
                                                                                                       '/dsgetdc:$env:USERDOMAIN\n'}}},
                                                          'tactic': 'discovery',
                                                          'technique': {'attack_id': 'T1018',
                                                                        'name': 'Remote '
                                                                                'System '
                                                                                'Discovery'}}},
 {'Mitre Stockpile - Identify the organizations mail server': {'description': 'Identify '
                                                                              'the '
                                                                              'organizations '
                                                                              'mail '
                                                                              'server',
                                                               'id': 'ce485320-41a4-42e8-a510-f5a8fe96a644',
                                                               'name': 'Discover '
                                                                       'Mail '
                                                                       'Server',
                                                               'platforms': {'darwin': {'sh': {'command': 'host '
                                                                                                          '"#{target.org.domain}" '
                                                                                                          '| '
                                                                                                          'grep '
                                                                                                          'mail '
                                                                                                          '| '
                                                                                                          'grep '
                                                                                                          '-oE '
                                                                                                          "'[^ "
                                                                                                          "]+$' "
                                                                                                          '| '
                                                                                                          'rev '
                                                                                                          '| '
                                                                                                          'cut '
                                                                                                          '-c '
                                                                                                          '2- '
                                                                                                          '| '
                                                                                                          'rev',
                                                                                               'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'target.org.emailhost'}]}}},
                                                                             'linux': {'sh': {'command': 'host '
                                                                                                         '"#{target.org.domain}" '
                                                                                                         '| '
                                                                                                         'grep '
                                                                                                         'mail '
                                                                                                         '| '
                                                                                                         'grep '
                                                                                                         '-oE '
                                                                                                         "'[^ "
                                                                                                         "]+$' "
                                                                                                         '| '
                                                                                                         'rev '
                                                                                                         '| '
                                                                                                         'cut '
                                                                                                         '-c '
                                                                                                         '2- '
                                                                                                         '| '
                                                                                                         'rev',
                                                                                              'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'target.org.emailhost'}]}}},
                                                                             'windows': {'psh': {'command': '(nslookup '
                                                                                                            '-querytype=mx '
                                                                                                            '#{target.org.domain}. '
                                                                                                            '| '
                                                                                                            'Select-String '
                                                                                                            '-pattern '
                                                                                                            "'mail' "
                                                                                                            '| '
                                                                                                            'Out-String).Trim()\n',
                                                                                                 'parsers': {'plugins.stockpile.app.parsers.basic': [{'source': 'target.org.emailhost'}]}}}},
                                                               'tactic': 'discovery',
                                                               'technique': {'attack_id': 'T1018',
                                                                             'name': 'Remote '
                                                                                     'System '
                                                                                     'Discovery'}}},
 {'Mitre Stockpile - Find hostname of remote IP in domain': {'description': 'Find '
                                                                            'hostname '
                                                                            'of '
                                                                            'remote '
                                                                            'IP '
                                                                            'in '
                                                                            'domain',
                                                             'id': 'fa4ed735-7006-4451-a578-b516f80e559f',
                                                             'name': 'Reverse '
                                                                     'nslookup '
                                                                     'IP',
                                                             'platforms': {'windows': {'psh': {'command': 'nslookup '
                                                                                                          '#{remote.host.ip}\n',
                                                                                               'parsers': {'plugins.stockpile.app.parsers.reverse_nslookup': [{'edge': 'has_ip',
                                                                                                                                                               'source': 'remote.host.fqdn',
                                                                                                                                                               'target': 'remote.host.ip'}]}}}},
                                                             'tactic': 'discovery',
                                                             'technique': {'attack_id': 'T1018',
                                                                           'name': 'Remote '
                                                                                   'System '
                                                                                   'Discovery'}}},
 {'Mitre Stockpile - Find hostname of remote host': {'description': 'Find '
                                                                    'hostname '
                                                                    'of remote '
                                                                    'host',
                                                     'id': 'fdf8bf36-797f-4157-805b-fe7c1c6fc903',
                                                     'name': 'Find Hostname',
                                                     'platforms': {'windows': {'psh': {'command': 'nbtstat '
                                                                                                  '-A '
                                                                                                  '#{remote.host.ip}'}}},
                                                     'tactic': 'discovery',
                                                     'technique': {'attack_id': 'T1018',
                                                                   'name': 'Remote '
                                                                           'System '
                                                                           'Discovery'}}},
 {'Threat Hunting Tables': {'chain_id': '100165',
                            'commandline_string': 'view /domain',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1018',
                            'mitre_caption': 'remote_discovery',
                            'os': 'windows',
                            'parent_process': 'net.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100166',
                            'commandline_string': '/server:',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'rare',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1018',
                            'mitre_caption': 'remote_discovery',
                            'os': 'windows',
                            'parent_process': 'qwinsta.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Threat Hunting Tables': {'chain_id': '100167',
                            'commandline_string': '/logfile= '
                                                  '/LogToConsole=false /U '
                                                  '*.dll',
                            'file_path': '',
                            'file_value': '',
                            'frequency': 'low',
                            'itw_sample': '',
                            'loaded_dll': '',
                            'mitre_attack': 'T1018',
                            'mitre_caption': 'execution',
                            'os': 'windows',
                            'parent_process': 'installutil.exe',
                            'registry_path': '',
                            'registry_value': '',
                            'sub_process_1': '',
                            'sub_process_2': ''}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1018',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_domain_controller":  '
                                                                                 '["T1018"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_domain_controller',
                                            'Technique': 'Remote System '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1018',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_domain_policy":  '
                                                                                 '["T1018"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_domain_policy',
                                            'Technique': 'Remote System '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1018',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_domain_trust":  '
                                                                                 '["T1018"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_domain_trust',
                                            'Technique': 'Remote System '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1018',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_forest":  '
                                                                                 '["T1018"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_forest',
                                            'Technique': 'Remote System '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1018',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_forest_domain":  '
                                                                                 '["T1018"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_forest_domain',
                                            'Technique': 'Remote System '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1018',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/powerview/get_site":  '
                                                                                 '["T1018"],',
                                            'Empire Module': 'powershell/situational_awareness/network/powerview/get_site',
                                            'Technique': 'Remote System '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1018',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"powershell/situational_awareness/network/reverse_dns":  '
                                                                                 '["T1018"],',
                                            'Empire Module': 'powershell/situational_awareness/network/reverse_dns',
                                            'Technique': 'Remote System '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1018',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/active_directory/get_computers":  '
                                                                                 '["T1018"],',
                                            'Empire Module': 'python/situational_awareness/network/active_directory/get_computers',
                                            'Technique': 'Remote System '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1018',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/active_directory/get_domaincontrollers":  '
                                                                                 '["T1018"],',
                                            'Empire Module': 'python/situational_awareness/network/active_directory/get_domaincontrollers',
                                            'Technique': 'Remote System '
                                                         'Discovery'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1018',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"python/situational_awareness/network/gethostbyname":  '
                                                                                 '["T1018"],',
                                            'Empire Module': 'python/situational_awareness/network/gethostbyname',
                                            'Technique': 'Remote System '
                                                         'Discovery'}}]
```

# Tactics


* [Discovery](../tactics/Discovery.md)


# Mitigations


* [Remote System Discovery Mitigation](../mitigations/Remote-System-Discovery-Mitigation.md)


# Actors


* [Threat Group-3390](../actors/Threat-Group-3390.md)

* [FIN6](../actors/FIN6.md)
    
* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)
    
* [Deep Panda](../actors/Deep-Panda.md)
    
* [FIN5](../actors/FIN5.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [APT3](../actors/APT3.md)
    
* [APT32](../actors/APT32.md)
    
* [Turla](../actors/Turla.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [FIN8](../actors/FIN8.md)
    
* [menuPass](../actors/menuPass.md)
    
* [Leafminer](../actors/Leafminer.md)
    
* [APT39](../actors/APT39.md)
    
* [Soft Cell](../actors/Soft-Cell.md)
    
* [Silence](../actors/Silence.md)
    
* [Wizard Spider](../actors/Wizard-Spider.md)
    
* [Rocke](../actors/Rocke.md)
    
* [Sandworm Team](../actors/Sandworm-Team.md)
    
