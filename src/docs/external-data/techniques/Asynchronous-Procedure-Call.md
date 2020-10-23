
# Asynchronous Procedure Call

## Description

### MITRE Description

> Adversaries may inject malicious code into processes via the asynchronous procedure call (APC) queue in order to evade process-based defenses as well as possibly elevate privileges. APC injection is a method of executing arbitrary code in the address space of a separate live process. 

APC injection is commonly performed by attaching malicious code to the APC Queue (Citation: Microsoft APC) of a process's thread. Queued APC functions are executed when the thread enters an alterable state.(Citation: Microsoft APC) A handle to an existing victim process is first created with native Windows API calls such as <code>OpenThread</code>. At this point <code>QueueUserAPC</code> can be used to invoke a function (such as <code>LoadLibrayA</code> pointing to a malicious DLL). 

A variation of APC injection, dubbed "Early Bird injection", involves creating a suspended process in which malicious code can be written and executed before the process' entry point (and potentially subsequent anti-malware hooks) via an APC. (Citation: CyberBit Early Bird Apr 2018) AtomBombing (Citation: ENSIL AtomBombing Oct 2016) is another variation that utilizes APCs to invoke malicious code previously written to the global atom table.(Citation: Microsoft Atom Table)

Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via APC injection may also evade detection from security products since the execution is masked under a legitimate process. 

## Aliases

```

```

## Additional Attributes

* Bypass: ['Application control', 'Anti-virus']
* Effective Permissions: None
* Network: None
* Permissions: None
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1055/004

## Potential Commands

```
PathToAtomicsFolder\T1055.004\bin\T1055.exe
```

## Commands Dataset

```
[{'command': 'PathToAtomicsFolder\\T1055.004\\bin\\T1055.exe\n',
  'name': None,
  'source': 'atomics/T1055.004/T1055.004.yaml'}]
```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json
[{'Atomic Red Team Test - Process Injection: Asynchronous Procedure Call': {'atomic_tests': [{'auto_generated_guid': '611b39b7-e243-4c81-87a4-7145a90358b1',
                                                                                              'description': 'Process '
                                                                                                             'Injection '
                                                                                                             'using '
                                                                                                             'C#\n'
                                                                                                             'reference: '
                                                                                                             'https://github.com/pwndizzle/c-sharp-memory-injection\n'
                                                                                                             'Excercises '
                                                                                                             'Five '
                                                                                                             'Techniques\n'
                                                                                                             '1. '
                                                                                                             'Process '
                                                                                                             'injection\n'
                                                                                                             '2. '
                                                                                                             'ApcInjectionAnyProcess\n'
                                                                                                             '3. '
                                                                                                             'ApcInjectionNewProcess\n'
                                                                                                             '4. '
                                                                                                             'IatInjection\n'
                                                                                                             '5. '
                                                                                                             'ThreadHijack\n'
                                                                                                             'Upon '
                                                                                                             'successful '
                                                                                                             'execution, '
                                                                                                             'cmd.exe '
                                                                                                             'will '
                                                                                                             'execute '
                                                                                                             'T1055.exe, '
                                                                                                             'which '
                                                                                                             'exercises '
                                                                                                             '5 '
                                                                                                             'techniques. '
                                                                                                             'Output '
                                                                                                             'will '
                                                                                                             'be '
                                                                                                             'via '
                                                                                                             'stdout.\n',
                                                                                              'executor': {'command': '#{exe_binary}\n',
                                                                                                           'name': 'command_prompt'},
                                                                                              'input_arguments': {'exe_binary': {'default': 'PathToAtomicsFolder\\T1055.004\\bin\\T1055.exe',
                                                                                                                                 'description': 'Output '
                                                                                                                                                'Binary',
                                                                                                                                 'type': 'Path'}},
                                                                                              'name': 'Process '
                                                                                                      'Injection '
                                                                                                      'via '
                                                                                                      'C#',
                                                                                              'supported_platforms': ['windows']}],
                                                                            'attack_technique': 'T1055.004',
                                                                            'display_name': 'Process '
                                                                                            'Injection: '
                                                                                            'Asynchronous '
                                                                                            'Procedure '
                                                                                            'Call'}}]
```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)

* [Privilege Escalation](../tactics/Privilege-Escalation.md)
    

# Mitigations


* [Behavior Prevention on Endpoint](../mitigations/Behavior-Prevention-on-Endpoint.md)


# Actors

None
