# CTF Platform Writeups

Investigation writeups for hands-on blue-team labs completed on public platforms (CyberDefenders, BTLO, Hack The Box). Each writeup reconstructs an incident from the provided evidence, documents the methodology, and states the findings with evidence.

Labs are investigated **cold** — findings are reasoned from the evidence before consulting any walkthrough.

## Index

| Platform | Lab | Category | Summary |
|---|---|---|---|
| CyberDefenders | [RetailBreach](./cyberdefenders/retailbreach/) | Network Forensics (PCAP) | Web intrusion: directory brute-forcing → stored XSS → session hijacking → directory traversal |
| CyberDefenders | [PoisonedCredentials](./cyberdefenders/poisonedcredentials/) | Network Forensics (PCAP) | LLMNR/NBT-NS poisoning → forced SMB authentication → NTLMv2 credential capture |
| CyberDefenders | [The Crime Lab](./cyberdefenders/the-crime-lab/) | Mobile Forensics (Android / ALEAPP) | Murder investigation: reconstructing a victim's timeline from phone artifacts |

## Structure

```
<platform>/<lab>/
├── README.md              full writeup with evidence and findings
├── images/                annotated tool screenshots
├── filter-queries/        display filters used (network labs)
└── artifact-sources/      artifact/module sources (forensics labs)
```
