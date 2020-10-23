
# LD_PRELOAD

## Description

### MITRE Description

> Adversaries may execute their own malicious payloads by hijacking the dynamic linker used to load libraries. The dynamic linker is used to load shared library dependencies needed by an executing program. The dynamic linker will typically check provided absolute paths and common directories for these dependencies, but can be overridden by shared objects specified by LD_PRELOAD to be loaded before all others.(Citation: Man LD.SO)(Citation: TLDP Shared Libraries)

Adversaries may set LD_PRELOAD to point to malicious libraries that match the name of legitimate libraries which are requested by a victim program, causing the operating system to load the adversary's malicious code upon execution of the victim program. LD_PRELOAD can be set via the environment variable or <code>/etc/ld.so.preload</code> file.(Citation: Man LD.SO)(Citation: TLDP Shared Libraries) Libraries specified by LD_PRELOAD with be loaded and mapped into memory by <code>dlopen()</code> and <code>mmap()</code> respectively.(Citation: Code Injection on Linux and macOS) (Citation: Uninformed Needle) (Citation: Phrack halfdead 1997)

LD_PRELOAD hijacking may grant access to the victim process's memory, system/network resources, and possibly elevated privileges. Execution via LD_PRELOAD hijacking may also evade detection from security products since the execution is masked under a legitimate process.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Linux']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1574/006

## Potential Commands

```
sudo sh -c 'echo #{path_to_shared_library} > /etc/ld.so.preload'
LD_PRELOAD=/tmp/T1574006.so ls
sudo sh -c 'echo /tmp/T1574006.so > /etc/ld.so.preload'
LD_PRELOAD=#{path_to_shared_library} ls
```

## Commands Dataset

```
[{'command': "sudo sh -c 'echo #{path_to_shared_library} > "
             "/etc/ld.so.preload'\n",
  'name': None,
  'source': 'atomics/T1574.006/T1574.006.yaml'},
 {'command': "sudo sh -c 'echo /tmp/T1574006.so > /etc/ld.so.preload'\n",
  'name': None,
  'source': 'atomics/T1574.006/T1574.006.yaml'},
 {'command': 'LD_PRELOAD=#{path_to_shared_library} ls\n',
  'name': None,
  'source': 'atomics/T1574.006/T1574.006.yaml'},
 {'command': 'LD_PRELOAD=/tmp/T1574006.so ls\n',
  'name': None,
  'source': 'atomics/T1574.006/T1574.006.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Hijack Execution Flow: LD_PRELOAD': {'atomic_tests': [{'auto_generated_guid': '39cb0e67-dd0d-4b74-a74b-c072db7ae991',
                                                                                 'dependencies': [{'description': 'The '
                                                                                                                  'shared '
                                                                                                                  'library '
                                                                                                                  'must '
                                                                                                                  'exist '
                                                                                                                  'on '
                                                                                                                  'disk '
                                                                                                                  'at '
                                                                                                                  'specified '
                                                                                                                  'location '
                                                                                                                  '(#{path_to_shared_library})\n',
                                                                                                   'get_prereq_command': 'gcc '
                                                                                                                         '-shared '
                                                                                                                         '-fPIC '
                                                                                                                         '-o '
                                                                                                                         '#{path_to_shared_library} '
                                                                                                                         '#{path_to_shared_library_source}\n',
                                                                                                   'prereq_command': 'if '
                                                                                                                     '[ '
                                                                                                                     '-f '
                                                                                                                     '#{path_to_shared_library '
                                                                                                                     ']; '
                                                                                                                     'then '
                                                                                                                     'exit '
                                                                                                                     '0; '
                                                                                                                     'else '
                                                                                                                     'exit '
                                                                                                                     '1; '
                                                                                                                     'fi;\n'}],
                                                                                 'dependency_executor_name': 'bash',
                                                                                 'description': 'This '
                                                                                                'test '
                                                                                                'adds '
                                                                                                'a '
                                                                                                'shared '
                                                                                                'library '
                                                                                                'to '
                                                                                                'the '
                                                                                                '`ld.so.preload` '
                                                                                                'list '
                                                                                                'to '
                                                                                                'execute '
                                                                                                'and '
                                                                                                'intercept '
                                                                                                'API '
                                                                                                'calls. '
                                                                                                'This '
                                                                                                'technique '
                                                                                                'was '
                                                                                                'used '
                                                                                                'by '
                                                                                                'threat '
                                                                                                'actor '
                                                                                                'Rocke '
                                                                                                'during '
                                                                                                'the '
                                                                                                'exploitation '
                                                                                                'of '
                                                                                                'Linux '
                                                                                                'web '
                                                                                                'servers. '
                                                                                                'This '
                                                                                                'requires '
                                                                                                'the '
                                                                                                '`glibc` '
                                                                                                'package.\n'
                                                                                                '\n'
                                                                                                'Upon '
                                                                                                'successful '
                                                                                                'execution, '
                                                                                                'bash '
                                                                                                'will '
                                                                                                'echo '
                                                                                                '`../bin/T1574.006.so` '
                                                                                                'to '
                                                                                                '/etc/ld.so.preload. \n',
                                                                                 'executor': {'cleanup_command': 'sudo '
                                                                                                                 'sed '
                                                                                                                 '-i '
                                                                                                                 "'\\~#{path_to_shared_library}~d' "
                                                                                                                 '/etc/ld.so.preload\n',
                                                                                              'command': 'sudo '
                                                                                                         'sh '
                                                                                                         '-c '
                                                                                                         "'echo "
                                                                                                         '#{path_to_shared_library} '
                                                                                                         '> '
                                                                                                         "/etc/ld.so.preload'\n",
                                                                                              'elevation_required': True,
                                                                                              'name': 'bash'},
                                                                                 'input_arguments': {'path_to_shared_library': {'default': '/tmp/T1574006.so',
                                                                                                                                'description': 'Path '
                                                                                                                                               'to '
                                                                                                                                               'a '
                                                                                                                                               'shared '
                                                                                                                                               'library '
                                                                                                                                               'object',
                                                                                                                                'type': 'Path'},
                                                                                                     'path_to_shared_library_source': {'default': 'PathToAtomicsFolder/T1574.006/src/Linux/T1574.006.c',
                                                                                                                                       'description': 'Path '
                                                                                                                                                      'to '
                                                                                                                                                      'a '
                                                                                                                                                      'shared '
                                                                                                                                                      'library '
                                                                                                                                                      'source '
                                                                                                                                                      'code',
                                                                                                                                       'type': 'Path'}},
                                                                                 'name': 'Shared '
                                                                                         'Library '
                                                                                         'Injection '
                                                                                         'via '
                                                                                         '/etc/ld.so.preload',
                                                                                 'supported_platforms': ['linux']},
                                                                                {'auto_generated_guid': 'bc219ff7-789f-4d51-9142-ecae3397deae',
                                                                                 'dependencies': [{'description': 'The '
                                                                                                                  'shared '
                                                                                                                  'library '
                                                                                                                  'must '
                                                                                                                  'exist '
                                                                                                                  'on '
                                                                                                                  'disk '
                                                                                                                  'at '
                                                                                                                  'specified '
                                                                                                                  'location '
                                                                                                                  '(#{path_to_shared_library})\n',
                                                                                                   'get_prereq_command': 'gcc '
                                                                                                                         '-shared '
                                                                                                                         '-fPIC '
                                                                                                                         '-o '
                                                                                                                         '#{path_to_shared_library} '
                                                                                                                         '#{path_to_shared_library_source}\n',
                                                                                                   'prereq_command': 'if '
                                                                                                                     '[ '
                                                                                                                     '-f '
                                                                                                                     '#{path_to_shared_library} '
                                                                                                                     ']; '
                                                                                                                     'then '
                                                                                                                     'exit '
                                                                                                                     '0; '
                                                                                                                     'else '
                                                                                                                     'exit '
                                                                                                                     '1; '
                                                                                                                     'fi;\n'}],
                                                                                 'dependency_executor_name': 'bash',
                                                                                 'description': 'This '
                                                                                                'test '
                                                                                                'injects '
                                                                                                'a '
                                                                                                'shared '
                                                                                                'object '
                                                                                                'library '
                                                                                                'via '
                                                                                                'the '
                                                                                                'LD_PRELOAD '
                                                                                                'environment '
                                                                                                'variable '
                                                                                                'to '
                                                                                                'execute. '
                                                                                                'This '
                                                                                                'technique '
                                                                                                'was '
                                                                                                'used '
                                                                                                'by '
                                                                                                'threat '
                                                                                                'actor '
                                                                                                'Rocke '
                                                                                                'during '
                                                                                                'the '
                                                                                                'exploitation '
                                                                                                'of '
                                                                                                'Linux '
                                                                                                'web '
                                                                                                'servers. '
                                                                                                'This '
                                                                                                'requires '
                                                                                                'the '
                                                                                                '`glibc` '
                                                                                                'package.\n'
                                                                                                '\n'
                                                                                                'Upon '
                                                                                                'successful '
                                                                                                'execution, '
                                                                                                'bash '
                                                                                                'will '
                                                                                                'utilize '
                                                                                                'LD_PRELOAD '
                                                                                                'to '
                                                                                                'load '
                                                                                                'the '
                                                                                                'shared '
                                                                                                'object '
                                                                                                'library '
                                                                                                '`/etc/ld.so.preload`. '
                                                                                                'Output '
                                                                                                'will '
                                                                                                'be '
                                                                                                'via '
                                                                                                'stdout.\n',
                                                                                 'executor': {'command': 'LD_PRELOAD=#{path_to_shared_library} '
                                                                                                         'ls\n',
                                                                                              'name': 'bash'},
                                                                                 'input_arguments': {'path_to_shared_library': {'default': '/tmp/T1574006.so',
                                                                                                                                'description': 'Path '
                                                                                                                                               'to '
                                                                                                                                               'a '
                                                                                                                                               'shared '
                                                                                                                                               'library '
                                                                                                                                               'object',
                                                                                                                                'type': 'Path'},
                                                                                                     'path_to_shared_library_source': {'default': 'PathToAtomicsFolder/T1574.006/src/Linux/T1574.006.c',
                                                                                                                                       'description': 'Path '
                                                                                                                                                      'to '
                                                                                                                                                      'a '
                                                                                                                                                      'shared '
                                                                                                                                                      'library '
                                                                                                                                                      'source '
                                                                                                                                                      'code',
                                                                                                                                       'type': 'Path'}},
                                                                                 'name': 'Shared '
                                                                                         'Library '
                                                                                         'Injection '
                                                                                         'via '
                                                                                         'LD_PRELOAD',
                                                                                 'supported_platforms': ['linux']}],
                                                               'attack_technique': 'T1574.006',
                                                               'display_name': 'Hijack '
                                                                               'Execution '
                                                                               'Flow: '
                                                                               'LD_PRELOAD'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Persistence](../tactics/Persistence.md)
    
* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Execution Prevention](../mitigations/Execution-Prevention.md)


# Actors


* [Rocke](../actors/Rocke.md)

