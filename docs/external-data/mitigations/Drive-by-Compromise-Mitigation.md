
# Drive-by Compromise Mitigation

## Description

### MITRE Description

> Drive-by compromise relies on there being a vulnerable piece of software on the client end systems. Use modern browsers with security features turned on. Ensure all browsers and plugins kept updated can help prevent the exploit phase of this technique.

For malicious code served up through ads, adblockers can help prevent that code from executing in the first place. Script blocking extensions can help prevent the execution of JavaScript that may commonly be used during the exploitation process.

Browser sandboxes can be used to mitigate some of the impact of exploitation, but sandbox escapes may still exist. (Citation: Windows Blogs Microsoft Edge Sandbox) (Citation: Ars Technica Pwn2Own 2017 VM Escape)

Other types of virtualization and application microsegmentation may also mitigate the impact of client-side exploitation. The risks of additional exploits and weaknesses in implementation may still exist. (Citation: Ars Technica Pwn2Own 2017 VM Escape)

Security applications that look for behavior used during exploitation such as Windows Defender Exploit Guard (WDEG) and the Enhanced Mitigation Experience Toolkit (EMET) can be used to mitigate some exploitation behavior. (Citation: TechNet Moving Beyond EMET) Control flow integrity checking is another way to potentially identify and stop a software exploit from occurring. (Citation: Wikipedia Control Flow Integrity) Many of these protections depend on the architecture and target application binary for compatibility.


# Techniques


* [Drive-by Compromise](../techniques/Drive-by-Compromise.md)

