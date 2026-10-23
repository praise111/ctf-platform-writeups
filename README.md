# CTF Platform Writeups

Investigation writeups for hands-on blue-team labs completed on public platforms (CyberDefenders, BTLO, Hack The Box). Each writeup reconstructs an incident from the provided evidence, documents the methodology, states the findings with evidence, and maps the activity to MITRE ATT&CK.

Labs are investigated **cold** — findings are reasoned from the evidence before consulting any walkthrough.

## Index

| Platform | Lab | Category | Summary |
|---|---|---|---|
| CyberDefenders | [RetailBreach](./cyberdefenders/retailbreach/) | Network Forensics (PCAP) | Web intrusion: directory brute-forcing → stored XSS → session hijacking → directory traversal |
| CyberDefenders | [PoisonedCredentials](./cyberdefenders/poisonedcredentials/) | Network Forensics (PCAP) | LLMNR/NBT-NS poisoning → forced SMB authentication → NTLMv2 credential capture |

## Structure

```
<platform>/<lab>/
├── README.md              full writeup with evidence and findings
├── images/                annotated Wireshark / tool screenshots
└── filter-queries/        the display filters / queries used
```
