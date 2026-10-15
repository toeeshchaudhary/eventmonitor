# EventMonitor

Consented session monitoring for event machines **we own**, used to verify that
submitted work was produced by the person who submitted it.

PowerShell agent (zero runtime deps, Windows PowerShell 5.1) + Bun collector with
SQLite storage and a read-only console.

---

## What it records

| type | what | default |
|---|---|---|
| `window` | foreground process + window title, idle transitions | on |
| `input` | keystroke **count** per focused window | on |
| `proc` | process start / stop | on |
| `shot` | downscaled JPEG screenshot every 120s | on |
| `redacted` | marker emitted instead of input/shot on excluded windows | on |
| `chars` | **actual characters typed** | **OFF** — requires `-Mode content -CaptureCharacters` |
| `agent` | start/stop, mode, AUP version | on |

Excluded windows (password managers, banking, sign-in, OTP) are suppressed:
no screenshot, no typing activity, no content.

---

## Architecture

```
  event machine (ours)                    collector box (LAN)
  +----------------------+                +----------------------------+
  | collect.ps1          |   HTTPS POST   | server.ts (bun)            |
  |  - consent gate      |  /ingest       |  - token auth per machine   |
  |  - window/input/proc | -------------> |  - SQLite (events.db)       |
  |  - screenshots       |  X-Machine-Id  |  - blobs/<machine>/*.jpg    |
  |  - DPAPI spool ----+ |  X-Token       |  - retention prune (hourly) |
  +--------------------|---+               |                            |
  | notice.ps1         |                   | public/index.html console  |
  |  [REC] watermark   |                   +----------------------------+
  +--------------------+
     spool at rest = DPAPI(CurrentUser).jpeg
```

Flow: agent appends DPAPI-encrypted events to a rotating spool file (4 MB), then
drains oldest-first to the collector. A failed upload never loses data — the
spool simply keeps growing and retries.

---

## Setup

### 1. Collector

```bash
cd collector
bun run server.ts --gen-token        # prints a machine token, repeat per machine
# edit collector.json: adminToken, machines{}, retentionDays, port
bun run server.ts
```

`collector.json`:

```json
{
  "host": "0.0.0.0",
  "port": 8787,
  "dataDir": "./data",
  "adminToken": "<>=16 chars, real one>",
  "retentionDays": 7,
  "machines": { "LAB-PC-01": { "token": "<token>", "label": "Lab PC 1" } }
}
```

The server **refuses to start** while any token is still `CHANGE-ME`.

### 2. Agent (per event machine, as admin)

```powershell
powershell -ExecutionPolicy Bypass -File install-agent.ps1 `
  -CollectorUrl https://collector.yourdomain.local `
  -MachineToken <token-from-collector> `
  -Operator "Toeesh Chaudhary" `
  -MachineId LAB-PC-01
```

This writes `data\consent.json`, registers autostart (scheduled task, or Startup
shortcut without admin), sets a logon banner, and starts the capture + watermark.

Optional, only when the task explicitly requires it:

```powershell
... -Mode content -CaptureCharacters
```

### 3. Console

`http://<collector>:8787/` — paste the **admin token**. Timeline (grouped by
session), screenshot gallery, type filter, live auto-refresh, JSONL export.

### 4. Teardown

```powershell
powershell -ExecutionPolicy Bypass -File uninstall-agent.ps1           # keeps local spool
powershell -ExecutionPolicy Bypass -File uninstall-agent.ps1 -PurgeData # deletes it
```

Removes the task/shortcut, stops processes, clears the banner, deletes consent.
Then prune the collector side once your retention window closes.

---

## Setting the machine id and station

Every event carries `machine`, `station` and `attendee`, so the evidence dump is
self-describing and you can see who was where without cross-referencing anything.

Set them at install time:

```powershell
.\Setup-EventMonitor.ps1 -Role Agent -CollectorUrl http://<collector>:8787 `
  -Operator "Toeesh Chaudhary" -MachineId LAB-PC-03 -Station "TABLE-2" -Attendee "Team Kryptix"
```

Change them **while the event is running** - no reinstall, no restart:

```powershell
.\Set-Identity.ps1 -Station "TABLE-4" -Attendee "Team Alpha"   # team moves tables
.\Set-Identity.ps1 -Show                                        # what is it set to now?
.\Set-Identity.ps1 -Station ""                                  # clear it
.\Set-Identity.ps1 -Station "TABLE-5" -Restart                  # apply instantly instead of ~20s
```

`-Table`, `-Seat`, `-System`, `-Bench`, `-Desk`, `-Workstation` are all aliases for
`-Station`; `-Team`/`-Person` alias `-Attendee`; `-Id` aliases `-MachineId`.

The agent re-reads `consent.json` every ~20 seconds and records an **`identity`
event with the from/to values** whenever it changes, then flushes immediately. So a
machine handed from Team Alpha to Team Beta mid-event leaves a clean, timestamped
handover record in the timeline and in the JSONL dump.

One caveat: changing `-MachineId` only changes the **label** on events. The binding
the collector files under is the token issued at enrollment, so the console keeps
listing the enrolled id. To change the enrolled id, re-run the setup command above
with the new `-MachineId`.

## Day-of checklist

- [ ] `aup.txt` printed and displayed at the desk (and ideally on the wall)
- [ ] Watermark `[REC] SESSION MONITORED - <id>` visible on every machine at login
- [ ] Logon banner appears before anyone can type
- [ ] Collector reachable from every machine (`/health`)
- [ ] `retentionDays` matches what `aup.txt` promises
- [ ] A named staff member is on duty to answer "what are you recording?"
- [ ] One unmonitored machine available for anyone who declines
- [ ] Recording is OFF for anyone who declines — no exceptions

**If an attendee asks, the honest answer is:** windows, applications, screenshots,
and *how much* you type. Not what you type, unless the task said so in writing.

---

## Limits — read before trusting the output

- Character capture is **approximate** (polling + US layout). It is a rough
  reconstruction, not a transcript. Do not present it as a verbatim record.
- If a machine has multiple simultaneous local users, the capture is ambiguous.
- The watermark is per-session; an attendee could cover it. Physical checks matter.
- Evidence is strong for "this window was focused, this much typing happened,
  here is a screenshot" and weak for proving authorship by itself. Corroborate
  with git signatures, submission timestamps, and check-in records.
- Plain `http://` collector URLs put evidence on the wire in clear text. Use TLS
  or an isolated wired/guest-segmented network.
- No legal advice here: retention windows, notice text and consent for minors are
  the organiser's call. Get the school/company to sign off on that before the event.

---

## Verified behaviour

Tested on Windows 11 / PowerShell 5.1 / Bun 1.4.3:

| check | result |
|---|---|
| all scripts parse | 5/5 clean |
| DPAPI encrypt/decrypt roundtrip | pass |
| live capture -> spool -> TLS POST -> SQLite | pass |
| screenshot stored + served as real JPEG | pass (`ff d8 ff`, `image/jpeg`) |
| spool rotation (6 events -> 1 file, 6 lines) | pass |
| ingest with wrong/unknown machine token | 401 |
| admin APIs without token | 401 |
| blob path traversal (`..%2f..`) | 400 |
| `-CaptureCharacters` without `-Mode content` | refused |
| collector with placeholder tokens | refuses to start |
| uninstall removes task, shortcut, consent, banner | pass (0 leftovers) |

Bugs found and fixed during testing, for reference:

1. `-f` string formatting choked on the JSON braces in the request body
   (`Input string was not in a correct format`) — body is now built by
   concatenation. The old code also masked the real error by throwing a second
   time inside the catch block.
2. The spool wrote **one file per event** (~10k files per machine per event).
   Now appends to a rotating file and drops BOM-less lines so reads are clean.
3. Blob filenames kept the `+` from the timezone offset and were rejected by the
   path validator, so every screenshot 400'd. Sanitisation is now a whitelist.
