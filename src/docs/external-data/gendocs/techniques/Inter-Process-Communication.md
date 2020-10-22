
# Inter-Process Communication

## Description

### MITRE Description

> Adversaries may abuse inter-process communication (IPC) mechanisms for local code or command execution. IPC is typically used by processes to share data, communicate with each other, or synchronize execution. IPC is also commonly used to avoid situations such as deadlocks, which occurs when processes are stuck in a cyclic waiting pattern. 

Adversaries may abuse IPC to execute arbitrary code or commands. IPC mechanisms may differ depending on OS, but typically exists in a form accessible through programming languages/libraries or native interfaces such as Windows [Dynamic Data Exchange](https://attack.mitre.org/techniques/T1559/002) or [Component Object Model](https://attack.mitre.org/techniques/T1559/001). Higher level execution mediums, such as those of [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059)s, may also leverage underlying IPC mechanisms.

## Aliases

```

```

## Additional Attributes

* Bypass: None
* Effective Permissions: None
* Network: None
* Permissions: ['Administrator', 'User', 'SYSTEM']
* Platforms: ['Windows']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1559

## Potential Commands

```

```

## Commands Dataset

```

```

## Potential Detections

```json

```

## Potential Queries

```json

```

## Raw Dataset

```json

```

# Tactics


* [Execution](../tactics/Execution.md)


# Mitigations


* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)

* [Software Configuration](../mitigations/Software-Configuration.md)
    
* [Disable or Remove Feature or Program](../mitigations/Disable-or-Remove-Feature-or-Program.md)
    
* [Application Isolation and Sandboxing](../mitigations/Application-Isolation-and-Sandboxing.md)
    
* [Behavior Prevention on Endpoint](../mitigations/Behavior-Prevention-on-Endpoint.md)
    

# Actors

None
