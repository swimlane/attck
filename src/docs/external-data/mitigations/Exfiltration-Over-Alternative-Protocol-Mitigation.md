
# Exfiltration Over Alternative Protocol Mitigation

## Description

### MITRE Description

> Follow best practices for network firewall configurations to allow only necessary ports and traffic to enter and exit the network. For example, if services like FTP are not required for sending information outside of a network, then block FTP-related ports at the network perimeter. Enforce proxies and use dedicated servers for services such as DNS and only allow those systems to communicate over respective ports/protocols, instead of all systems within a network. (Citation: TechNet Firewall Design) These actions will help reduce command and control and exfiltration path opportunities.

Network intrusion detection and prevention systems that use network signatures to identify traffic for specific adversary command and control infrastructure and malware can be used to mitigate activity at the network level. Signatures are often for unique indicators within protocols and may be based on the specific obfuscation technique used by a particular adversary or tool, and will likely be different across various malware families and versions. Adversaries will likely change tool command and control signatures over time or construct protocols in such a way to avoid detection by common defensive tools. (Citation: University of Birmingham C2)


# Techniques


* [Exfiltration Over Alternative Protocol](../techniques/Exfiltration-Over-Alternative-Protocol.md)

