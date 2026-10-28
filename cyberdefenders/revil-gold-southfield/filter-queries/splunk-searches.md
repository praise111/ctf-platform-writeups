# Splunk Searches — REvil / GOLD SOUTHFIELD

SPL used during the hunt, in order.

## Orientation — the file-creation burst (and false positive)
```
index=revil "event.code"=11
| bucket _time span=1m
| stats count, values(winlog.event_date.TargetFilename) as CreatedFiles by _time, winlog.event_data, Image
| where count > 50
```
Surfaces the 600+ files from `svchost.exe` in a tight window. **Before trusting it**, verify the process identity:
```
index=revil "event.code"=1 winlog.event_data.Image="*svchost.exe*"
```
Legitimate svchost: `C:\Windows\System32\svchost.exe`, parent `services.exe`, normal `-k` command line. The created files trace to `C:\Windows\SoftwareDistribution\Download\...\$dpx$.tmp\` → **Windows Update, not ransomware.**

## Q1 — Ransom note (text-file creations)
```
index=revil "event.code"=11 winlog.event_data.TargetFilename="*.txt"
```

## Q2 / Q3 — Ransomware process (PID + executable location)
Identify the executable behind the note activity; read `ProcessId` and `Image`:
```
index=revil "event.code"=1 winlog.event_data.Image="*facebook assistant.exe*"
```

## Q4 — Shadow-copy deletion (child of the dropper)
```
index=revil "event.code"=1 winlog.event_data.ParentImage="*facebook assistant.exe*"
```
The child `powershell.exe` runs `powershell -e <base64>`. Decode with CyberChef: **From Base64 → Decode text → UTF-16LE (1200)** →
```
Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}
```

## Q5 — Executable hash
```
index=revil "event.code"=1 winlog.event_data.Image="*facebook assistant.exe*"
```
Read the `Hashes` field (MD5 / SHA1 / SHA256).

## Q6 — Onion domain
Not in the host telemetry — take the executable's SHA-256 to a threat-intel service (e.g. tri.age / VirusTotal) to recover the full REvil ransom-note template, which contains the TOR payment URL.

---

### Reference
```
# Common Sysmon event codes used here
event.code=1    # Process creation (Image, ParentImage, CommandLine, Hashes)
event.code=11   # File creation (TargetFilename)
event.code=13   # Registry value set (e.g. desktop Wallpaper change)
```
