PC Audit 0.4.4
==============

A read-only health scan for Windows 10 and 11 PCs. It checks hardware, drivers, BIOS,
Windows Update history, event logs and crashes. It compares installed versions with the
manufacturers' latest, then shows a report. The scan itself changes nothing.
New in 0.4.0: download buttons in the report, and a Change history tab.


How to run
----------
1. Copy PCAudit.exe anywhere (a USB stick is fine) and double-click it.
2. Answer "Yes" to the Windows administrator prompt.
3. Watch the progress (usually 2-5 minutes; the Windows Update and Catalog checks take longest).
4. The report opens in the same window when the scan is done.

Reports are saved to:  Documents\PC Audit reports\<PC name>_<date>\
Each folder has the HTML report, audit.json (raw data) and scan-log.txt.


What's fixed in 0.4.4
---------------------
"Pending restart: Pending file rename operations" no longer sticks after restarts.
Many programs leave temporary-file cleanups for Windows to do at the next boot, and some
add them back after every boot. Now only real file replacements count as a pending
restart, and not when the same entries were already there before the last restart.
The Windows page lists the files, so you can see which program leaves them.


What's new in 0.4.3
-------------------
"Show issues from: All / 30 days / 7 days / 1 day" at the bottom of the side menu.
It hides events, blue screens, failed updates and failed driver installs that last
happened longer ago than that (counted back from the scan). Problems that exist right
now always show. Hidden items are listed in a folded list. The choice is remembered
for this PC.


What's new in 0.4.2
-------------------
Dismiss old problems. Findings, event log rows, failed updates, blue screens and failed
driver installs have a Dismiss button. A dismissed item stays hidden until it happens
again after you dismissed it, then comes back marked "Happened again". Dismissed items
are listed in a folded list with a Restore button. The list is kept per PC in
Documents\PC Audit reports\<PC name>.dismissed.jsonl.

Re-logged crash reports are counted once. Windows can log the same GPU hang or crash
report many times (a stuck error-report queue re-logs it at every boot). Each dump is
now counted once and dated by when it actually happened.


What's fixed in 0.4.1
---------------------
Gigabyte boards whose support page covers several revisions (for example
"B650 GAMING X AX (rev. 1.0/1.1/1.2)") are found again, so the BIOS list and latest
version show up. If Gigabyte's site can't be reached, the BIOS panel now links to a
search for the board's support page instead of Gigabyte's front page.


Downloading and installing updates (new in 0.4.0)
-------------------------------------------------
On the Updates page, newer drivers have buttons:
  Download & install          Microsoft Update Catalog drivers (.cab)
  Download & open installer   NVIDIA, AMD and board-maker driver packages
  Download                    BIOS files (download only)

What happens when you click one:
1. The file is downloaded to  Downloads\PC Audit\<PC name>\<date>\  and kept there
   so you can review it later. Only the makers' and Microsoft's own download
   servers are allowed.
2. Its digital signature is checked. Catalog drivers must be signed by Microsoft,
   NVIDIA drivers by NVIDIA, AMD drivers by AMD. Anything else is kept but never run.
3. PC Audit asks you before going further:
   - Drivers: it creates a System Restore point, then installs with Windows' own
     driver installer (pnputil). Roll back in Device Manager if needed.
   - Installers: it opens the maker's installer, which asks its own questions.
   - BIOS: flash it from the BIOS itself (Instant Flash, M-Flash, EZ Flash, Q-Flash).
One download runs at a time. Every step is written to
Downloads\PC Audit\<PC name>\downloads.log.


Change history (new in 0.4.0)
-----------------------------
Each scan compares itself with the previous scan of the same PC and shows what changed:
driver updates, BIOS and Windows versions, devices added or removed, problems fixed.
Changes are marked "PC Audit" when they were installed through PC Audit or match what
PC Audit recommended last time. Windows' own driver install record is listed too.
Keep the report folders in Documents\PC Audit reports for this to work.


If your antivirus still complains
---------------------------------
PCAudit.exe is not code-signed yet, so some products judge it on reputation alone:
- Windows SmartScreen: click "More info", then "Run anyway".
- Microsoft Defender or another product: report it as a false positive. Defender:
  https://www.microsoft.com/wdsi/filesubmission (choose "Incorrectly detected as malware").
- A code-signed build is the lasting fix. The source package includes the signing command.


Options (run from a command prompt)
-----------------------------------
  PCAudit.exe -Offline            skip all online lookups
  PCAudit.exe -SkipCatalog        skip the Microsoft Update Catalog check (saves 1-2 minutes)
  PCAudit.exe -NoWindowsUpdate    don't ask Windows Update what it is offering
  PCAudit.exe -EventDays 60       scan 60 days of event logs instead of 30


Requirements
------------
- Windows 10 or 11 (64-bit, 32-bit or ARM). .NET Framework 4.8 and Windows PowerShell 5.1 are built in.
- For the report window: Microsoft Edge WebView2 Runtime, which is included with Windows 11
  and with current Windows 10. Without it, the report opens in an Edge window instead.
- Internet access for the update checks. Without it the scan still runs; the update
  checks are just skipped.


Files the app keeps
-------------------
%LOCALAPPDATA%\PCAudit\0.4.4\  holds the report template, the WebView2 viewer files and the
viewer's cache. You can delete this folder at any time.

The same scan is available as plain PowerShell scripts in the separate "scripts" download.
