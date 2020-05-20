
# Install Root Certificate

## Description

### MITRE Description

> Root certificates are used in public key cryptography to identify a root certificate authority (CA). When a root certificate is installed, the system or application will trust certificates in the root's chain of trust that have been signed by the root certificate. (Citation: Wikipedia Root Certificate) Certificates are commonly used for establishing secure TLS/SSL communications within a web browser. When a user attempts to browse a website that presents a certificate that is not trusted an error message will be displayed to warn the user of the security risk. Depending on the security settings, the browser may not allow the user to establish a connection to the website.

Installation of a root certificate on a compromised system would give an adversary a way to degrade the security of that system. Adversaries have used this technique to avoid security warnings prompting users when compromised systems connect over HTTPS to adversary controlled web servers that spoof legitimate websites in order to collect login credentials. (Citation: Operation Emmental)

Atypical root certificates have also been pre-installed on systems by the manufacturer or in the software supply chain and were used in conjunction with malware/adware to provide a man-in-the-middle capability for intercepting information transmitted over secure TLS/SSL communications. (Citation: Kaspersky Superfish)

Root certificates (and their associated chains) can also be cloned and reinstalled. Cloned certificate chains will carry many of the same metadata characteristics of the source and can be used to sign malicious code that may then bypass signature validation tools (ex: Sysinternals, antivirus, etc.) used to block execution and/or uncover artifacts of Persistence. (Citation: SpectorOps Code Signing Dec 2017)

In macOS, the Ay MaMi malware uses <code>/usr/bin/security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain /path/to/malicious/cert</code> to install a malicious certificate as a trusted root certificate into the system keychain. (Citation: objective-see ay mami 2018)

## Aliases

```

```

## Additional Attributes

* Bypass: ['Digital Certificate Validation']
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'User']
* Platforms: ['Linux', 'Windows', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1130

## Potential Commands

```
openssl genrsa -out rootCA.key 4096
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 365 -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" -out #{cert_filename}

if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -le "5" ];
then
  cat rootCA.crt >> /etc/pki/tls/certs/ca-bundle.crt
else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -ge "7" ];
  cp rootCA.crt /etc/pki/ca-trust/source/anchors/
  update-ca-trust
fi

openssl genrsa -out #{key_filename} 4096
openssl req -x509 -new -nodes -key #{key_filename} -sha256 -days 365 -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" -out rootCA.crt

if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -le "5" ];
then
  cat rootCA.crt >> /etc/pki/tls/certs/ca-bundle.crt
else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -ge "7" ];
  cp rootCA.crt /etc/pki/ca-trust/source/anchors/
  update-ca-trust
fi

mv #{cert_filename} /usr/local/share/ca-certificates
echo sudo update-ca-certificates

mv rootCA.crt /usr/local/share/ca-certificates
echo sudo update-ca-certificates

sudo security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" "#{cert_filename}"

sudo security add-trusted-cert -d -r trustRoot -k "/Library/Keychains/System.keychain" "rootCA.crt"

$cert = Import-Certificate -FilePath rootCA.cer -CertStoreLocation Cert:\LocalMachine\My
Move-Item -Path $cert.PSPath -Destination "Cert:\LocalMachine\Root"

```

## Commands Dataset

```
[{'command': 'openssl genrsa -out rootCA.key 4096\n'
             'openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 365 '
             '-subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" '
             '-out #{cert_filename}\n'
             '\n'
             "if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -le "
             '"5" ];\n'
             'then\n'
             '  cat rootCA.crt >> /etc/pki/tls/certs/ca-bundle.crt\n'
             "else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) "
             '-ge "7" ];\n'
             '  cp rootCA.crt /etc/pki/ca-trust/source/anchors/\n'
             '  update-ca-trust\n'
             'fi\n',
  'name': None,
  'source': 'atomics/T1130/T1130.yaml'},
 {'command': 'openssl genrsa -out #{key_filename} 4096\n'
             'openssl req -x509 -new -nodes -key #{key_filename} -sha256 -days '
             '365 -subj '
             '"/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" -out '
             'rootCA.crt\n'
             '\n'
             "if [ $(rpm -q --queryformat '%{VERSION}' centos-release) -le "
             '"5" ];\n'
             'then\n'
             '  cat rootCA.crt >> /etc/pki/tls/certs/ca-bundle.crt\n'
             "else if [ $(rpm -q --queryformat '%{VERSION}' centos-release) "
             '-ge "7" ];\n'
             '  cp rootCA.crt /etc/pki/ca-trust/source/anchors/\n'
             '  update-ca-trust\n'
             'fi\n',
  'name': None,
  'source': 'atomics/T1130/T1130.yaml'},
 {'command': 'mv #{cert_filename} /usr/local/share/ca-certificates\n'
             'echo sudo update-ca-certificates\n',
  'name': None,
  'source': 'atomics/T1130/T1130.yaml'},
 {'command': 'mv rootCA.crt /usr/local/share/ca-certificates\n'
             'echo sudo update-ca-certificates\n',
  'name': None,
  'source': 'atomics/T1130/T1130.yaml'},
 {'command': 'sudo security add-trusted-cert -d -r trustRoot -k '
             '"/Library/Keychains/System.keychain" "#{cert_filename}"\n',
  'name': None,
  'source': 'atomics/T1130/T1130.yaml'},
 {'command': 'sudo security add-trusted-cert -d -r trustRoot -k '
             '"/Library/Keychains/System.keychain" "rootCA.crt"\n',
  'name': None,
  'source': 'atomics/T1130/T1130.yaml'},
 {'command': '$cert = Import-Certificate -FilePath rootCA.cer '
             '-CertStoreLocation Cert:\\LocalMachine\\My\n'
             'Move-Item -Path $cert.PSPath -Destination '
             '"Cert:\\LocalMachine\\Root"\n',
  'name': None,
  'source': 'atomics/T1130/T1130.yaml'}]
```

## Potential Detections

```json
[{'data_source': ['4657', 'Reg Audit']},
 {'data_source': ['SSL/TLS inspection']},
 {'data_source': ['Digital Certificate Logs']},
 {'data_source': ['4657', 'Reg Audit']},
 {'data_source': ['SSL/TLS inspection']},
 {'data_source': ['Digital Certificate Logs']}]
```

## Potential Queries

```json
[{'name': 'Install Root Certificates',
  'product': 'Azure Sentinel',
  'query': 'Sysmon| where (EventID == 12 or EventID == 13 or EventID == 14)and '
           'process_path !contains "svchost.exe"and (registry_key_path '
           'contains '
           '"*\\\\SOFTWARE\\\\Microsoft\\\\EnterpriseCertificates\\\\Root\\\\Certificates\\\\*"or '
           'registry_key_path contains '
           '"*\\\\Microsoft\\\\SystemCertificates\\\\Root\\\\Certificates\\\\*")'}]
```

## Raw Dataset

```json
[{'Atomic Red Team Test - Install Root Certificate': {'atomic_tests': [{'auto_generated_guid': '9c096ec4-fd42-419d-a762-d64cc950627e',
                                                                        'description': 'Creates '
                                                                                       'a '
                                                                                       'root '
                                                                                       'CA '
                                                                                       'with '
                                                                                       'openssl\n',
                                                                        'executor': {'command': 'openssl '
                                                                                                'genrsa '
                                                                                                '-out '
                                                                                                '#{key_filename} '
                                                                                                '4096\n'
                                                                                                'openssl '
                                                                                                'req '
                                                                                                '-x509 '
                                                                                                '-new '
                                                                                                '-nodes '
                                                                                                '-key '
                                                                                                '#{key_filename} '
                                                                                                '-sha256 '
                                                                                                '-days '
                                                                                                '365 '
                                                                                                '-subj '
                                                                                                '"/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" '
                                                                                                '-out '
                                                                                                '#{cert_filename}\n'
                                                                                                '\n'
                                                                                                'if '
                                                                                                '[ '
                                                                                                '$(rpm '
                                                                                                '-q '
                                                                                                '--queryformat '
                                                                                                "'%{VERSION}' "
                                                                                                'centos-release) '
                                                                                                '-le '
                                                                                                '"5" '
                                                                                                '];\n'
                                                                                                'then\n'
                                                                                                '  '
                                                                                                'cat '
                                                                                                'rootCA.crt '
                                                                                                '>> '
                                                                                                '/etc/pki/tls/certs/ca-bundle.crt\n'
                                                                                                'else '
                                                                                                'if '
                                                                                                '[ '
                                                                                                '$(rpm '
                                                                                                '-q '
                                                                                                '--queryformat '
                                                                                                "'%{VERSION}' "
                                                                                                'centos-release) '
                                                                                                '-ge '
                                                                                                '"7" '
                                                                                                '];\n'
                                                                                                '  '
                                                                                                'cp '
                                                                                                'rootCA.crt '
                                                                                                '/etc/pki/ca-trust/source/anchors/\n'
                                                                                                '  '
                                                                                                'update-ca-trust\n'
                                                                                                'fi\n',
                                                                                     'name': 'sh'},
                                                                        'input_arguments': {'cert_filename': {'default': 'rootCA.crt',
                                                                                                              'description': 'Path '
                                                                                                                             'of '
                                                                                                                             'the '
                                                                                                                             'CA '
                                                                                                                             'certificate '
                                                                                                                             'we '
                                                                                                                             'create',
                                                                                                              'type': 'Path'},
                                                                                            'key_filename': {'default': 'rootCA.key',
                                                                                                             'description': 'Key '
                                                                                                                            'we '
                                                                                                                            'create '
                                                                                                                            'that '
                                                                                                                            'is '
                                                                                                                            'used '
                                                                                                                            'to '
                                                                                                                            'create '
                                                                                                                            'the '
                                                                                                                            'CA '
                                                                                                                            'certificate',
                                                                                                             'type': 'Path'}},
                                                                        'name': 'Install '
                                                                                'root '
                                                                                'CA '
                                                                                'on '
                                                                                'CentOS/RHEL',
                                                                        'supported_platforms': ['linux']},
                                                                       {'auto_generated_guid': '53bcf8a0-1549-4b85-b919-010c56d724ff',
                                                                        'dependencies': [{'description': 'Verify '
                                                                                                         'the '
                                                                                                         'certificate '
                                                                                                         'exists. '
                                                                                                         'It '
                                                                                                         'generates '
                                                                                                         'if '
                                                                                                         'not '
                                                                                                         'on '
                                                                                                         'disk.\n',
                                                                                          'get_prereq_command': 'if '
                                                                                                                '[ '
                                                                                                                '! '
                                                                                                                '-f '
                                                                                                                '#{key_filename} '
                                                                                                                ']; '
                                                                                                                'then '
                                                                                                                'openssl '
                                                                                                                'genrsa '
                                                                                                                '-out '
                                                                                                                '#{key_filename} '
                                                                                                                '4096; '
                                                                                                                'fi;\n'
                                                                                                                'openssl '
                                                                                                                'req '
                                                                                                                '-x509 '
                                                                                                                '-new '
                                                                                                                '-nodes '
                                                                                                                '-key '
                                                                                                                '#{key_filename} '
                                                                                                                '-sha256 '
                                                                                                                '-days '
                                                                                                                '365 '
                                                                                                                '-subj '
                                                                                                                '"/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" '
                                                                                                                '-out '
                                                                                                                '#{cert_filename}\n',
                                                                                          'prereq_command': 'if '
                                                                                                            '[ '
                                                                                                            '-f '
                                                                                                            '#{cert_filename} '
                                                                                                            ']; '
                                                                                                            'then '
                                                                                                            'exit '
                                                                                                            '0; '
                                                                                                            'else '
                                                                                                            'exit '
                                                                                                            '1; '
                                                                                                            'fi;\n'}],
                                                                        'dependency_executor_name': 'command_prompt',
                                                                        'description': 'Creates '
                                                                                       'a '
                                                                                       'root '
                                                                                       'CA '
                                                                                       'with '
                                                                                       'openssl\n',
                                                                        'executor': {'command': 'mv '
                                                                                                '#{cert_filename} '
                                                                                                '/usr/local/share/ca-certificates\n'
                                                                                                'echo '
                                                                                                'sudo '
                                                                                                'update-ca-certificates\n',
                                                                                     'elevation_required': True,
                                                                                     'name': 'sh'},
                                                                        'input_arguments': {'cert_filename': {'default': 'rootCA.crt',
                                                                                                              'description': 'CA '
                                                                                                                             'file '
                                                                                                                             'name',
                                                                                                              'type': 'Path'},
                                                                                            'key_filename': {'default': 'rootCA.key',
                                                                                                             'description': 'Key '
                                                                                                                            'we '
                                                                                                                            'create '
                                                                                                                            'that '
                                                                                                                            'is '
                                                                                                                            'used '
                                                                                                                            'to '
                                                                                                                            'create '
                                                                                                                            'the '
                                                                                                                            'CA '
                                                                                                                            'certificate',
                                                                                                             'type': 'Path'}},
                                                                        'name': 'Install '
                                                                                'root '
                                                                                'CA '
                                                                                'on '
                                                                                'Debian/Ubuntu',
                                                                        'supported_platforms': ['linux']},
                                                                       {'auto_generated_guid': 'cc4a0b8c-426f-40ff-9426-4e10e5bf4c49',
                                                                        'dependencies': [{'description': 'Verify '
                                                                                                         'the '
                                                                                                         'certificate '
                                                                                                         'exists. '
                                                                                                         'It '
                                                                                                         'generates '
                                                                                                         'if '
                                                                                                         'not '
                                                                                                         'on '
                                                                                                         'disk.\n',
                                                                                          'get_prereq_command': 'if '
                                                                                                                '[ '
                                                                                                                '! '
                                                                                                                '-f '
                                                                                                                '#{key_filename} '
                                                                                                                ']; '
                                                                                                                'then '
                                                                                                                'openssl '
                                                                                                                'genrsa '
                                                                                                                '-out '
                                                                                                                '#{key_filename} '
                                                                                                                '4096; '
                                                                                                                'fi;\n'
                                                                                                                'openssl '
                                                                                                                'req '
                                                                                                                '-x509 '
                                                                                                                '-new '
                                                                                                                '-nodes '
                                                                                                                '-key '
                                                                                                                '#{key_filename} '
                                                                                                                '-sha256 '
                                                                                                                '-days '
                                                                                                                '365 '
                                                                                                                '-subj '
                                                                                                                '"/C=US/ST=Denial/L=Springfield/O=Dis/CN=www.example.com" '
                                                                                                                '-out '
                                                                                                                '#{cert_filename}\n',
                                                                                          'prereq_command': 'if '
                                                                                                            '[ '
                                                                                                            '-f '
                                                                                                            '#{cert_filename} '
                                                                                                            ']; '
                                                                                                            'then '
                                                                                                            'exit '
                                                                                                            '0; '
                                                                                                            'else '
                                                                                                            'exit '
                                                                                                            '1; '
                                                                                                            'fi;\n'}],
                                                                        'dependency_executor_name': 'command_prompt',
                                                                        'description': 'Creates '
                                                                                       'a '
                                                                                       'root '
                                                                                       'CA '
                                                                                       'with '
                                                                                       'openssl\n',
                                                                        'executor': {'command': 'sudo '
                                                                                                'security '
                                                                                                'add-trusted-cert '
                                                                                                '-d '
                                                                                                '-r '
                                                                                                'trustRoot '
                                                                                                '-k '
                                                                                                '"/Library/Keychains/System.keychain" '
                                                                                                '"#{cert_filename}"\n',
                                                                                     'elevation_required': True,
                                                                                     'name': 'command_prompt'},
                                                                        'input_arguments': {'cert_filename': {'default': 'rootCA.crt',
                                                                                                              'description': 'CA '
                                                                                                                             'file '
                                                                                                                             'name',
                                                                                                              'type': 'Path'},
                                                                                            'key_filename': {'default': 'rootCA.key',
                                                                                                             'description': 'Key '
                                                                                                                            'we '
                                                                                                                            'create '
                                                                                                                            'that '
                                                                                                                            'is '
                                                                                                                            'used '
                                                                                                                            'to '
                                                                                                                            'create '
                                                                                                                            'the '
                                                                                                                            'CA '
                                                                                                                            'certificate',
                                                                                                             'type': 'Path'}},
                                                                        'name': 'Install '
                                                                                'root '
                                                                                'CA '
                                                                                'on '
                                                                                'macOS',
                                                                        'supported_platforms': ['macos']},
                                                                       {'auto_generated_guid': '76f49d86-5eb1-461a-a032-a480f86652f1',
                                                                        'dependencies': [{'description': 'Verify '
                                                                                                         'the '
                                                                                                         'certificate '
                                                                                                         'exists. '
                                                                                                         'It '
                                                                                                         'generates '
                                                                                                         'if '
                                                                                                         'not '
                                                                                                         'on '
                                                                                                         'disk.\n',
                                                                                          'get_prereq_command': '$cert '
                                                                                                                '= '
                                                                                                                'New-SelfSignedCertificate '
                                                                                                                '-DnsName '
                                                                                                                'atomicredteam.com '
                                                                                                                '-CertStoreLocation '
                                                                                                                'cert:\\LocalMachine\\My\n'
                                                                                                                'Export-Certificate '
                                                                                                                '-Type '
                                                                                                                'CERT '
                                                                                                                '-Cert  '
                                                                                                                'Cert:\\LocalMachine\\My\\$cert.Thumbprint '
                                                                                                                '-FilePath '
                                                                                                                '#{pfx_path}\n'
                                                                                                                'Get-ChildItem '
                                                                                                                'Cert:\\LocalMachine\\My\\$($cert.Thumbprint) '
                                                                                                                '| '
                                                                                                                'Remove-Item        \n',
                                                                                          'prereq_command': 'if '
                                                                                                            '(Test-Path '
                                                                                                            '#{cert_filename}) '
                                                                                                            '{ '
                                                                                                            'exit '
                                                                                                            '0 '
                                                                                                            '} '
                                                                                                            'else '
                                                                                                            '{ '
                                                                                                            'exit '
                                                                                                            '1 '
                                                                                                            '}\n'}],
                                                                        'dependency_executor_name': 'powershell',
                                                                        'description': 'Creates '
                                                                                       'a '
                                                                                       'root '
                                                                                       'CA '
                                                                                       'with '
                                                                                       'Powershell\n',
                                                                        'executor': {'cleanup_command': '$cert '
                                                                                                        '= '
                                                                                                        'Import-Certificate '
                                                                                                        '-FilePath '
                                                                                                        '#{pfx_path} '
                                                                                                        '-CertStoreLocation '
                                                                                                        'Cert:\\LocalMachine\\My\n'
                                                                                                        'Get-ChildItem '
                                                                                                        'Cert:\\LocalMachine\\My\\$($cert.Thumbprint) '
                                                                                                        '| '
                                                                                                        'Remove-Item\n'
                                                                                                        'Get-ChildItem '
                                                                                                        'Cert:\\LocalMachine\\Root\\$($cert.Thumbprint) '
                                                                                                        '| '
                                                                                                        'Remove-Item\n',
                                                                                     'command': '$cert '
                                                                                                '= '
                                                                                                'Import-Certificate '
                                                                                                '-FilePath '
                                                                                                '#{pfx_path} '
                                                                                                '-CertStoreLocation '
                                                                                                'Cert:\\LocalMachine\\My\n'
                                                                                                'Move-Item '
                                                                                                '-Path '
                                                                                                '$cert.PSPath '
                                                                                                '-Destination '
                                                                                                '"Cert:\\LocalMachine\\Root"\n',
                                                                                     'elevation_required': True,
                                                                                     'name': 'command_prompt'},
                                                                        'input_arguments': {'pfx_path': {'default': 'rootCA.cer',
                                                                                                         'description': 'Path '
                                                                                                                        'of '
                                                                                                                        'the '
                                                                                                                        'certificate',
                                                                                                         'type': 'Path'}},
                                                                        'name': 'Install '
                                                                                'root '
                                                                                'CA '
                                                                                'on '
                                                                                'Windows',
                                                                        'supported_platforms': ['windows']}],
                                                      'attack_technique': 'T1130',
                                                      'display_name': 'Install '
                                                                      'Root '
                                                                      'Certificate'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations

None

# Actors

None
