# Volatility 3 Commands — Volatility Traces

Plugins/commands used during the investigation, in order. (`-f memory.dmp` omitted for brevity.)

## Orientation — find the PowerShell and its parent
```
python3 vol.py -f memory.dmp windows.pstree | grep -i powershell
```
Two PowerShell processes (6980, 7656) share PPID 4596 — but 4596 is absent from pstree/pslist.

## The key pivot — recover the hidden/terminated parent
```
python3 vol.py -f memory.dmp windows.psscan | grep 4596
```
psscan carves `_EPROCESS` from memory directly, so it recovers terminated/exited/hidden processes. Reveals PID 4596 = `InvoiceCheckList.exe`, and its children: powershell (6980, 7656), RegSvcs.exe (×several), schtasks.exe (3512).

## Q4 / Q5 — read the malicious command lines
```
python3 vol.py -f memory.dmp windows.cmdline --pid 6980
python3 vol.py -f memory.dmp windows.cmdline --pid 7656
```
Both run `Add-MpPreference -ExclusionPath <file>` — excluding InvoiceCheckList.exe and HcdmIYYf.exe.
> Note: `windows.cmdline` does NOT return args for the terminated `schtasks.exe` (its PEB/command line is no longer resident). Scheduled-task details for a terminated schtasks must be recovered from the registry (`TaskCache`) or the on-disk Task XML instead.

## Q3 (supporting) — confirm process injection
```
python3 vol.py -f memory.dmp windows.malfind
```
Across the RegSvcs.exe instances, only PID 6796 shows a private memory region beginning with `4D 5A` (MZ) — an injected PE (process hollowing, T1055).

## Q7 — resolve the owning account
```
python3 vol.py -f memory.dmp windows.getsids --pid 6980
```
SID `S-1-5-21-1649652813-3480061347-1948202237-1001` → account `Lee`.

---

### Plugin reference
```
windows.pstree    # process tree (active, linked processes)
windows.pslist    # active process list
windows.psscan    # scan memory for _EPROCESS (recovers terminated/hidden)
windows.cmdline   # per-process command-line arguments
windows.malfind   # injected / executable private memory regions
windows.getsids   # owning account SIDs for a process
```
