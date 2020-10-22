
# File and Directory Permissions Modification

## Description

### MITRE Description

> Adversaries may modify file or directory permissions/attributes to evade access control lists (ACLs) and access protected files.(Citation: Hybrid Analysis Icacls1 June 2018)(Citation: Hybrid Analysis Icacls2 May 2018) File and directory permissions are commonly managed by ACLs configured by the file or directory owner, or users with the appropriate permissions. File and directory ACL implementations vary by platform, but generally explicitly designate which users or groups can perform which actions (read, write, execute, etc.).

Modifications may include changing specific access rights, which may require taking ownership of a file or directory and/or elevated permissions depending on the file or directory’s existing permissions. This may enable malicious activity such as modifying, replacing, or deleting specific files or directories. Specific file and directory modifications may be a required step for many techniques, such as establishing Persistence via [Accessibility Features](https://attack.mitre.org/techniques/T1546/008), [Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037), [.bash_profile and .bashrc](https://attack.mitre.org/techniques/T1546/004), or tainting/hijacking other instrumental binary/configuration files via [Hijack Execution Flow](https://attack.mitre.org/techniques/T1574).

## Aliases

```

```

## Additional Attributes

* Bypass: ['File system access controls']
* Effective Permissions: None
* Network: None
* Permissions: ['User', 'Administrator', 'SYSTEM', 'root']
* Platforms: ['Linux', 'Windows', 'macOS']
* Remote: None
* Type: attack-pattern
* Wiki: https://attack.mitre.org/techniques/T1222

## Potential Commands

```
```
chmod 766 test1.txt
chmod u+x test1.txt
chmod o-x test1.txt
```
```
chown ec2-user:ec2-user test1.txt
```
```

## Commands Dataset

```
[{'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': 'chmod 766 test1.txt',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'chmod u+x test1.txt',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': 'chmod o-x test1.txt',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'},
 {'command': 'chown ec2-user:ec2-user test1.txt',
  'name': None,
  'source': 'Kirtar22/Litmus_Test'},
 {'command': '```', 'name': None, 'source': 'Kirtar22/Litmus_Test'}]
```

## Potential Detections

```json
[{'data_source': 'auditlogs (audit.rules)'},
 {'data_source': 'bash_history logs'}]
```

## Potential Queries

```json
[{'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=linux_audit syscall=90 OR syscall=91 OR '
           'sycall=268 | table msg,syscall,syscall_name,success,auid,comm,exe'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype=linux_audit syscall=92 OR syscall=93 OR '
           'syscall=94 OR syscall=260 comm!=splunkd | table'},
 {'name': None,
  'product': 'Splunk',
  'query': 'msg,syscall,syscall_name,success,auid,comm,exe'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': '-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 '
           '-F auid!=-1 -F key=perm_mod'},
 {'name': None,
  'product': 'Splunk',
  'query': '-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F '
           'auid>=1000 -F auid!=-1 -F key=perm_mod'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype="bash_history" bash_command="chmod *" | '
           'table host,user_name,bash_command'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None, 'product': 'Splunk', 'query': '```'},
 {'name': None,
  'product': 'Splunk',
  'query': 'index=linux sourcetype="bash_history" bash_command="chown *" | '
           'table host,user_name,bash_command'},
 {'name': None, 'product': 'Splunk', 'query': '```'}]
```

## Raw Dataset

```json

```

# Tactics


* [Defense Evasion](../tactics/Defense-Evasion.md)


# Mitigations


* [Privileged Account Management](../mitigations/Privileged-Account-Management.md)

* [Restrict File and Directory Permissions](../mitigations/Restrict-File-and-Directory-Permissions.md)
    

# Actors

None
