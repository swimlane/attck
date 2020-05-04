
# Credential Dumping Mitigation

## Description

### MITRE Description

> ### Windows
Monitor/harden access to LSASS and SAM table with tools that allow process whitelisting. Limit credential overlap across systems to prevent lateral movement opportunities using [Valid Accounts](https://attack.mitre.org/techniques/T1078) if passwords and hashes are obtained. Ensure that local administrator accounts have complex, unique passwords across all systems on the network. Do not put user or admin domain accounts in the local administrator groups across systems unless they are tightly controlled, as this is often equivalent to having a local administrator account with the same password on all systems. Follow best practices for design and administration of an enterprise network to limit privileged account use across administrative tiers. (Citation: Microsoft Securing Privileged Access)

On Windows 8.1 and Windows Server 2012 R2, enable Protected Process Light for LSA. (Citation: Microsoft LSA)

Identify and block potentially malicious software that may be used to dump credentials by using whitelisting (Citation: Beechey 2010) tools, like AppLocker, (Citation: Windows Commands JPCERT) (Citation: NSA MS AppLocker) or Software Restriction Policies (Citation: Corio 2008) where appropriate. (Citation: TechNet Applocker vs SRP)

With Windows 10, Microsoft implemented new protections called Credential Guard to protect the LSA secrets that can be used to obtain credentials through forms of credential dumping. It is not configured by default and has hardware and firmware system requirements. (Citation: TechNet Credential Guard) It also does not protect against all forms of credential dumping. (Citation: GitHub SHB Credential Guard)

Manage the access control list for “Replicating Directory Changes” and other permissions associated with domain controller replication. (Citation: AdSecurity DCSync Sept 2015) (Citation: Microsoft Replication ACL)

Consider disabling or restricting NTLM traffic. (Citation: Microsoft Disable NTLM Nov 2012)

### Linux
Scraping the passwords from memory requires root privileges. Follow best practices in restricting access to escalated privileges to avoid hostile programs from accessing such sensitive regions of memory.


# Techniques


* [Credential Dumping](../techniques/Credential-Dumping.md)

