# PCDoc 0.4.4: scripts

A read-only health scan for Windows 10/11 troubleshooting. It collects hardware, driver, Windows Update and log information and produces one HTML report. **The scan installs and changes nothing on the PC.** Downloading and installing updates is a separate helper (`Invoke-PCDocAction.ps1`) that the PCDoc app runs only when you click a button and confirm.

## Files

| File | Purpose |
|---|---|
| `Invoke-PCDoc.ps1` | The scanner (PowerShell 5.1, built into Windows 10/11 — nothing to install) |
| `report-template.html` | Report layout; must sit next to the script |
| `Invoke-PCDocAction.ps1` | Download and install helper used by the app's buttons (see below). Not needed for a scan |
| `Run-PCDoc.cmd` | Double-click launcher: asks for admin rights, runs the full scan including the Windows Update check |

Copy the folder to a USB stick and run it from there.

## Running

**Easiest:** double-click `Run-PCDoc.cmd` and accept the admin prompt.

**Manually** (PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File .\Invoke-PCDoc.ps1 -CheckWindowsUpdate
```

Options:

| Parameter | Default | Meaning |
|---|---|---|
| `-CheckWindowsUpdate` | off | Ask Windows Update what is currently offered (software and drivers). Read-only search; needs internet; 1–5 min |
| `-EventDays 60` | 30 | How many days of event logs to scan |
| `-DriverAgeYears 2` | 3 | Flag third-party drivers older than this |
| `-OutputDir D:\Reports` | Desktop\PCDoc\<PC>_<time> | Where to write the report |
| `-SkipCatalog` | off | Skip the per-device Microsoft Update Catalog check (saves 1–2 minutes) |
| `-Offline` | off | Skip the online lookups (manufacturer BIOS/driver lists, GPU driver versions) |
| `-NoOpen` | off | Don't open the report when finished |

Output: `PCDoc_<computer>.html` (open in any browser, works offline) plus `audit.json` (raw data for the Phase 2 online checker).

Run it as administrator. Without admin rights, CBS.log, disk wear/temperature, Secure Boot, TPM and dump-file listings are missing; the report says what was skipped.

If Windows blocks the files after downloading: right-click → Properties → **Unblock**, or `Get-ChildItem .\ | Unblock-File`.

## What it checks

- **System**: maker and model. Custom builds (MSI/ASUS/Gigabyte/ASRock boards) are detected from the motherboard when the system fields say "To Be Filled By O.E.M.". Also BIOS version and age, boot mode, Secure Boot, TPM, CPU microcode, RAM modules (rated vs running speed), GPUs, disks (health, wear, firmware) and free space.
- **Drivers & devices**: every device with driver version, date, provider, INF and hardware IDs. Flags: *Problem* (Device Manager error code), *No driver*, *Generic driver* (Microsoft basic driver on GPU/audio/LAN/chipset), *Old driver*, *Unsigned*. Each device gets links:
  - **MS Catalog (exact)**: drivers for this exact device and subsystem
  - **MS Catalog (same chip, any OEM)**: drivers other manufacturers published for the same chip (the cross-vendor tier)
  - Intel / AMD / NVIDIA driver pages where relevant, plus a web search
- **Windows**: version, build, support end date, previous versions it was upgraded from, pending restarts (pending file renames count only when real files are waiting to be replaced, and not when a program re-adds them after every boot), update policies (WSUS leftovers, drivers excluded, service disabled).
- **Windows Update**: full history. Each failure is classified as *Resolved*, *Superseded* (a later cumulative update made it irrelevant), *Still pending* (still offered) or *Unresolved*, with error-code explanations and repeat-failure detection.
- **Event logs**: errors grouped by source/ID and matched against known driver/hardware patterns:
  - GPU resets (TDR) and graphics driver crashes
  - Storage resets and disk errors
  - WHEA hardware errors
  - Drivers that failed to load
  - USB, Bluetooth and network driver errors
  - ACPI/BIOS errors
  
  Known harmless noise (DCOM 10016) is hidden by default. Events are linked back to the device where possible.
- **Crashes**: BSODs with bugcheck names, dump files, live-kernel (GPU hang) events, and a 12-month reliability timeline.
- **Logs**: failed driver installs from `setupapi.dev.log`, component-store errors from `CBS.log`, failed or rolled-back feature upgrades from the Panther logs.

## Safety rules built in

- BIOS/firmware links point only to the system maker for the exact model. Never flash firmware from another model or maker.
- "Same chip, any OEM" drivers usually work but can lose maker-specific features (audio tuning, hotkeys, power management). On laptops, prefer the OEM version for audio and graphics.

## Updates tab (online lookups)

The **Updates** tab checks the manufacturers' own download lists. The scan is still read-only: nothing is downloaded or installed.

| Maker | What it finds |
|---|---|
| ASRock | Direct board page, full BIOS list (installed vs latest, betas marked), Windows driver list |
| MSI | Direct support page, BIOS list (matches MSI's `7C91vAL2`-style names to the installed version), driver list |
| ASUS | Direct support page, BIOS list (boards and laptops), driver list |
| Gigabyte | Direct page for the right revision, BIOS list (stable vs beta `F20a`-style), driver list, warning if the board revision is ambiguous |
| NVIDIA GPUs | Latest Game Ready driver vs installed |
| Microsoft Update Catalog | For every chip on a vendor driver (or a generic Windows driver): newest driver in the same family, newest overall (a different driver branch is labelled), and what was published for this exact board. Only drivers that apply to this Windows version are counted. |
| AMD | Latest AMD Chipset Software (compared with the installed version) and AMD's Adrenalin auto-detect installer for Radeon graphics |
| Intel GPUs | Link to Intel's own detection tool |
| HP | BIOS list from HP's per-platform catalog (`ftp.hp.com/pub/pcbios/<platform ID>`), mostly business models |
| Dell | Dell Command Update catalog for the system ID: BIOS list and Dell's driver list |
| Lenovo | Lenovo's update catalog by machine type (ThinkPad, ThinkCentre, ThinkStation, ThinkBook) |
| Any PC maker | The BIOS that Windows Update has for this PC, found in the Microsoft Update Catalog by the firmware ID (UEFI ESRT). Used for HP consumer models, Lenovo IdeaPad / Legion / Yoga, Acer, Microsoft Surface, Samsung, Razer, Huawei, Dynabook, Fujitsu, Medion and others, and as a fallback when the maker's own list can't be read |
| Others | Support links for Biostar, Supermicro, Colorful, Maxsun, NZXT, EVGA, Apple (Boot Camp), Framework, LG, VAIO, Xiaomi, Panasonic and Getac |

Driver rows compare the maker's latest version with the installed device driver or driver package. They're compared by version where the numbering schemes match, otherwise by release date. *Generic Windows driver* means Windows' built-in driver is in use where the maker offers a real one.

If a site blocks the request (ASRock uses bot protection), the row shows the direct link instead of a guess. Problems are listed under "Lookup problems".

## Change history

Every scan compares itself with the previous scan of the same PC (the newest `<PC>_<date>` folder next to its own output folder that has an `audit.json`). The **Change history** tab lists:

- **Since the last scan**: driver updates and rollbacks, BIOS and Windows build changes, devices added or removed, problems fixed or new. Each change says who made it, checked in this order:
  1. *Installed through PCDoc*: recorded in the downloads log by the app's buttons.
  2. *Recommended by PCDoc*: the new version is one the previous scan recommended (Catalog, board maker or graphics maker).
  3. *Windows Update*: matches a successful driver entry in the Windows Update history.
  4. Windows' own install log (`setupapi.dev.log`): *Windows (device detected)*, *Device Manager*, *Installer or pnputil*.
  5. Otherwise *Other (not recommended by PCDoc)*.
- **Downloads through PCDoc**: everything the buttons downloaded, checked, installed or opened.
- **Driver installs recorded by Windows**: the full successful-install timeline from `setupapi.dev.log`; installs before the last scan are folded away.

Keep the report folders together (the app uses `Documents\PCDoc reports`) so the history works.

## Dismissing old problems

Fixed a problem but the report keeps showing its old events? In the app, findings, event log rows, failed updates, blue screens and failed driver installs have a **Dismiss** button. A dismissed item is hidden until it **happens again after you dismissed it**; then it comes back marked *Happened again*. Dismissing the blue screens also hides the crash records they leave in the event log (bugcheck reports and Kernel-Power 41). Dismissed items stay listed in a folded "dismissed" list with a **Restore** button.

**Show issues from: All / 30 days / 7 days / 1 day** (bottom of the side menu) hides every dated issue (events, blue screens, failed updates, failed driver installs) whose last occurrence is older than that, counted back from the scan. Problems that exist right now (a device with an error, an update available, Windows out of support) always show. Hidden rows are listed in the same folded list. The choice is remembered per PC.

Dismissals are kept per PC in `Documents\PCDoc reports\<PC>.dismissed.jsonl` (one JSON line per change; the newest line for each item wins, and a `window` line holds the time-window choice), so they apply to every later scan of that PC.

**Re-logged crash reports.** Windows Error Reporting logs Event 1001 when it *processes* a report, not when the problem happened, and a stuck report queue re-logs the same dumps at every boot. PCDoc now counts each dump file or report ID once and dates it by the dump's own timestamp, so thousands of entries become the handful of real occurrences ("3, logged 120 times").

## Download and install helper

`Invoke-PCDocAction.ps1 -AuditJson <scan>\audit.json -ActionId a3 -Stage Prepare|Install|Launch` runs one of the scan's suggested actions (listed in `audit.json` under `Actions`). The app runs it for you; each stage is separate so you confirm before anything changes.

- **Prepare** downloads to `Downloads\PCDoc\<PC>\<date>\<update>\`, from an allow-list of maker and Microsoft download hosts (HTTPS only, redirects checked), then checks the digital signature. Catalog `.cab` files are unpacked and their catalog must be signed by Microsoft. NVIDIA and AMD installers must be signed by NVIDIA or AMD. Anything unsigned or signed by someone else is kept for inspection but never run.
- **Install** (driver packages): creates a System Restore point, then installs with Windows' `pnputil /add-driver … /install`, and reads back the device's driver version.
- **Launch** (maker installers): re-checks the signature and opens the maker's own installer, which asks its own questions.
- BIOS files are only downloaded. Flash them from the BIOS (Instant Flash, M-Flash, EZ Flash, Q-Flash).

Every step is logged to `Downloads\PCDoc\<PC>\downloads.log` (one JSON object per line), which the next scan uses for the Change history.

## Roadmap

- **Next:** HP and Lenovo driver lists (the BIOS is covered), and Acer's own download list.
- Intel graphics and Wi-Fi: direct downloads (currently the Intel page opens instead).
- Optional: decode minidumps automatically when WinDbg (cdb) is present.
