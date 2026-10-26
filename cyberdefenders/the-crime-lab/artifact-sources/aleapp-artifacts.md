# ALEAPP Artifact Sources — The Crime Lab

Which ALEAPP report module (and underlying source file) each finding was recovered from. This is the mobile-forensics equivalent of a filter list: the "where I looked" for every answer.

## Workflow
1. Compress the provided Android filesystem folder into a `.zip` or `.tar` archive.
2. Run ALEAPP against the archive to generate the interactive HTML report.
3. Start with **Device Information** and **Accounts** to establish ownership (Mohamed Ahmed; Google + Discord).
4. Work the questions by navigating to the modules below.

## Per-question sources

| Q | Finding | ALEAPP module | Source file |
|---|---|---|---|
| Q1 | Trading app SHA-256 | Installed Apps → `installedappsGass` | `data/data/com.google.android.gms/databases/gass.db` |
| Q2 | Amount owed (250,000 EGP) | SMS & MMS → `SMS Messages` | `com.android.providers.telephony` (mmssms.db) |
| Q3 | Creditor name (Shady Wahab) | Contacts → `Contacts` | `data/data/com.android.providers.contacts/databases/contacts2.db` |
| Q4 | Location (Ritz-Carlton, Cairo) | Recent Activity → `Recent Activity` (cached map snapshot) | system recent-tasks / snapshot cache |
| Q5 | Destination (Las Vegas) | Google Photos (saved ticket image) | `com.google.android.apps.photos` media cache |
| Q6 | Meeting point (The Mob Museum) | Discord Chats → `Discord - Cached Messages (API cache)` | `com.discord` cache |

## Supporting modules referenced
- **Call Logs** — the ~10 unanswered calls from Shady Wahab preceding the SMS threat.
- **Web History / Web Visits (Chromium)** — the victim researching how to change an already-booked flight after the threat.
- **Device Information / Accounts / Android Users and Profiles** — ownership (Mohamed Ahmed) and linked Google/Discord accounts.
- **Power Events / system logs** — the factory reset event (2023-09-20 23:55:49).

## Note on timestamps
ALEAPP displays timestamps in **UTC** (e.g., the Discord reply: `2023-09-20 20:46:02.237000+00:00`). The device and victim were in **Cairo (UTC+2/+3)** — convert accordingly when stating local event times. Relative ordering of events is unaffected by the timezone.
