# Wireshark Display Filters — PoisonedCredentials

Filters used during the investigation, in order.

## Orientation
Statistics → Protocol Hierarchy — confirm LLMNR and NBT-NS are unusually prominent (heavy name-resolution fallback).

```
llmnr
nbns
```

## Q1 — Mistyped query from the victim (NBT-NS requests)
```
ip.addr == 192.168.232.162 and nbns.flags.response == 0
```
`nbns.flags.response == 0` = queries only. Reveals the mistyped name `FILESHAARE<20>`.

## Q2 — Rogue machine (NBT-NS responses to the bogus query)
```
ip.addr == 192.168.232.162 and nbns.flags.response == 1
```
Whoever answers a query for a non-existent name is the poisoner (`192.168.232.215`).

## Q3 — Second victim (all poisoned responses from the rogue host)
```
(ip.addr == 192.168.232.215 and llmnr and dns.flags.response == 1) or nbns.flags.response == 1
```
Lists the rogue host's LLMNR + NBT-NS responses; read the destinations to find victims (`192.168.232.176`).

## Q4 / Q5 — Credential capture (SMB / NTLM)
Follow the SMB session between a victim and the rogue host and inspect the NTLM session-setup messages:
- **NTLMSSP_AUTH** (victim → rogue): Domain name, User name, Host name, Session Key.
- **NTLMSSP_CHALLENGE** (rogue → victim): NTLM Server Challenge + Target Info (NetBIOS computer name).

Useful filters:
```
# All SMB2 traffic
smb2

# Isolate the NTLM security blob
ntlmssp

# Traffic to/from the rogue host
ip.addr == 192.168.232.215
```

---

### Reference — key field values
```
# Query / response flag
nbns.flags.response == 0   # query
nbns.flags.response == 1   # response
dns.flags.response == 1    # LLMNR uses the DNS dissector

# LLMNR runs on UDP 5355 (multicast 224.0.0.252)
# NBT-NS runs on UDP 137 (broadcast)
```
