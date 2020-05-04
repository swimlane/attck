
# Process Injection Mitigation

## Description

### MITRE Description

> This type of attack technique cannot be easily mitigated with preventive controls since it is based on the abuse of operating system design features. For example, mitigating specific Windows API calls will likely have unintended side effects, such as preventing legitimate software (i.e., security products) from operating properly. Efforts should be focused on preventing adversary tools from running earlier in the chain of activity and on identification of subsequent malicious behavior. (Citation: GDSecurity Linux injection)

Identify or block potentially malicious software that may contain process injection functionality by using whitelisting (Citation: Beechey 2010) tools, like AppLocker, (Citation: Windows Commands JPCERT) (Citation: NSA MS AppLocker) or Software Restriction Policies (Citation: Corio 2008) where appropriate. (Citation: TechNet Applocker vs SRP)

Utilize Yama  (Citation: Linux kernel Yama) to mitigate ptrace based process injection by restricting the use of ptrace to privileged users only. Other mitigation controls involve the deployment of security kernel modules that provide advanced access control and process restrictions such as SELinux  (Citation: SELinux official), grsecurity  (Citation: grsecurity official), and AppArmor  (Citation: AppArmor official).


# Techniques


* [Process Injection](../techniques/Process-Injection.md)

