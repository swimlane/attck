
# Kerberoasting Mitigation

## Description

### MITRE Description

> Ensure strong password length (ideally 25+ characters) and complexity for service accounts and that these passwords periodically expire. (Citation: AdSecurity Cracking Kerberos Dec 2015) Also consider using Group Managed Service Accounts or another third party product such as password vaulting. (Citation: AdSecurity Cracking Kerberos Dec 2015)

Limit service accounts to minimal required privileges, including membership in privileged groups such as Domain Administrators. (Citation: AdSecurity Cracking Kerberos Dec 2015)

Enable AES Kerberos encryption (or another stronger encryption algorithm), rather than RC4, where possible. (Citation: AdSecurity Cracking Kerberos Dec 2015)


# Techniques


* [Kerberoasting](../techniques/Kerberoasting.md)

