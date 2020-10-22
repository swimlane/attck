
# Kernel Modules and Extensions Mitigation

## Description

### MITRE Description

> Common tools for detecting Linux rootkits include: rkhunter (Citation: SourceForge rkhunter), chrootkit (Citation: Chkrootkit Main), although rootkits may be designed to evade certain detection tools.

LKMs and Kernel extensions require root level permissions to be installed. Limit access to the root account and prevent users from loading kernel modules and extensions through proper privilege separation and limiting Privilege Escalation opportunities.

Application whitelisting and software restriction tools, such as SELinux, can also aide in restricting kernel module loading. (Citation: Kernel.org Restrict Kernel Module)


# Techniques


* [Kernel Modules and Extensions](../techniques/Kernel-Modules-and-Extensions.md)

