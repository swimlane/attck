
# Control Panel Items Mitigation

## Description

### MITRE Description

> This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of operating system design features. For example, mitigating specific Windows API calls and/or execution of particular file extensions will likely have unintended side effects, such as preventing legitimate software (i.e., drivers and configuration tools) from operating properly. Efforts should be focused on preventing adversary tools from running earlier in the chain of activity and on identification of subsequent malicious behavior.

Restrict storage and execution of Control Panel items to protected directories, such as <code>C:\Windows</code>, rather than user directories.

Index known safe Control Panel items and block potentially malicious software using whitelisting (Citation: Beechey 2010) tools like AppLocker (Citation: Windows Commands JPCERT) (Citation: NSA MS AppLocker) that are capable of auditing and/or blocking unknown executable files.

Consider fully enabling User Account Control (UAC) to impede system-wide changes from illegitimate administrators. (Citation: Microsoft UAC)


# Techniques


* [Control Panel Items](../techniques/Control-Panel-Items.md)

