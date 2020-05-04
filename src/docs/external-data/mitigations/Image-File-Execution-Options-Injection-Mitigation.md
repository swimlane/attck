
# Image File Execution Options Injection Mitigation

## Description

### MITRE Description

> This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of operating system design features. For example, mitigating all IFEO will likely have unintended side effects, such as preventing legitimate software (i.e., security products) from operating properly. (Citation: Microsoft IFEOorMalware July 2015) Efforts should be focused on preventing adversary tools from running earlier in the chain of activity and on identifying subsequent malicious behavior.

Identify and block potentially malicious software that may be executed through IFEO by using whitelisting (Citation: Beechey 2010) tools, like AppLocker, (Citation: Windows Commands JPCERT) (Citation: NSA MS AppLocker) that are capable of auditing and/or blocking unknown executables.


# Techniques


* [Image File Execution Options Injection](../techniques/Image-File-Execution-Options-Injection.md)

