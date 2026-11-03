# Changelog

## 0.4.4
- "Pending file rename operations" no longer counts as a pending restart when it holds only temp-file cleanups, or when a program re-adds the same entries after every boot. The Windows page lists the files.

## 0.4.3
- "Show issues from: All / 30 days / 7 days / 1 day" hides dated issues older than the chosen window. Current problems always show. Remembered per PC.

## 0.4.2
- Dismiss old findings, event log entries, failed updates, blue screens and failed driver installs. They come back, marked "Happened again", if they recur.
- Crash reports re-logged by Windows Error Reporting are counted once and dated by the dump file.

## 0.4.1
- Gigabyte boards whose support page covers several revisions (for example "rev. 1.0/1.1/1.2") are found again.

## 0.4.0
- Download buttons: Catalog drivers, NVIDIA and AMD installers, board-maker packages and BIOS files, with signature checks and confirmation before installing.
- Change history tab, with attribution to PC Audit, Windows Update or other sources.
- AMD chipset and Adrenalin checks.

## 0.3.0
- The scan runs inside PCAudit.exe with Windows' own PowerShell engine (no separate powershell.exe), which stops antivirus false alarms.

## 0.2.0 and earlier
- Single-window app with progress and the report in the same window; dark report with folded "no issues" sections; Microsoft Update Catalog checks; maker BIOS and driver lookups.
