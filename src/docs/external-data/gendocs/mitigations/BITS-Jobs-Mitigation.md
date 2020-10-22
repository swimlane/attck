
# BITS Jobs Mitigation

## Description

### MITRE Description

> This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of operating system design features. For example, disabling all BITS functionality will likely have unintended side effects, such as preventing legitimate software patching and updating. Efforts should be focused on preventing adversary tools from running earlier in the chain of activity and on identification of subsequent malicious behavior. (Citation: Mondok Windows PiggyBack BITS May 2007)

Modify network and/or host firewall rules, as well as other network controls, to only allow legitimate BITS traffic.

Consider limiting access to the BITS interface to specific users or groups. (Citation: Symantec BITS May 2007)

Consider reducing the default BITS job lifetime in Group Policy or by editing the <code>JobInactivityTimeout</code> and <code>MaxDownloadTime</code> Registry values in <code> HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\BITS</code>. (Citation: Microsoft BITS)


# Techniques


* [BITS Jobs](../techniques/BITS-Jobs.md)

