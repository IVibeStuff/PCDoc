# PC Audit

A health check for Windows 10 and 11 PCs, built for troubleshooting. It inventories the hardware and drivers, compares them with the manufacturers' latest BIOS and driver releases and the Microsoft Update Catalog, reads the Windows Update history and the event logs, and shows the result in one report.

The scan only reads. Updates are downloaded and installed only when you click a button and confirm.

## What it does

- **Hardware and drivers**: every device with its driver version, date and provider, with links to the maker's support page. Custom builds are identified from the motherboard.
- **Updates**: latest BIOS and drivers from ASRock, ASUS, Gigabyte and MSI; NVIDIA and AMD graphics drivers; AMD chipset software; newer drivers for the same chip in the Microsoft Update Catalog, including ones published by other makers.
- **Download and install**: downloads go to `Downloads\PC Audit\<PC>\<date>\` and are kept for review. Only the makers' and Microsoft's own download servers are allowed, every file's digital signature is checked, and nothing is installed or opened without asking. Driver installs create a System Restore point first. BIOS files are download-only.
- **Windows Update**: the full update history, with each failure marked as fixed by a later update, superseded, or still unresolved.
- **Event logs and crashes**: driver and hardware errors grouped by source, blue screens, GPU hangs and dump files. Crash reports that Windows re-logs at every boot are counted once.
- **Change history**: what changed since the previous scan of the same PC, and whether PC Audit recommended or installed it.
- **Dismiss and time window**: hide old problems you've dealt with. They come back if they happen again.

## Download

Get `PCAudit-<version>.zip` from [Releases](../../releases), unzip it and run `PCAudit.exe`. It asks for administrator rights once.

Requirements: Windows 10 or 11. .NET Framework 4.8 and Windows PowerShell 5.1 are built in. The report window uses the Microsoft Edge WebView2 Runtime, which comes with Windows 11 and current Windows 10; without it the report opens in an Edge window.

The EXE is not code-signed yet, so SmartScreen may warn the first time ("More info" > "Run anyway").

The same scan also runs as plain PowerShell: see [`scripts/README.md`](scripts/README.md).

## Repository layout

| Path | What it is |
|---|---|
| `src/` | The Windows app (WinForms, .NET Framework 4.8, C# 5): progress window, report viewer (WebView2), download/install and dismiss handling |
| `scripts/` | The scanner (`Invoke-PCAudit.ps1`), the download/install helper (`Invoke-PCAuditAction.ps1`) and the report template. Embedded in the EXE at build time |
| `lib/` | Microsoft WebView2 SDK files (Microsoft.Web.WebView2 1.0.3856.49, redistributable), embedded in the EXE |
| `build/` | Windows resources (manifest, icon, version info) and the Linux build script |

## Build

**Windows**: run `build-windows.cmd`. It uses the C# compiler that ships with Windows, so nothing needs installing. Output: `dist\PCAudit.exe`.

**Linux** (Mono): `build/build-linux-mono.sh`.

To sign the EXE: `signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a dist\PCAudit.exe`

## Version bump

Change `Version` and the assembly attributes in `src/PCAudit.cs` and `$ToolVersion` in `scripts/Invoke-PCAudit.ps1`, then regenerate the resources with `python build/mkres.py <version>.0 build/app.ico build/app.res`.
