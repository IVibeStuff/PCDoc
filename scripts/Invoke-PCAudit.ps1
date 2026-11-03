<#
.SYNOPSIS
    PC Audit - Phase 1: read-only hardware, driver, Windows Update and log health scan.

.DESCRIPTION
    Collects (never changes) information about this PC:
      - System, BIOS/UEFI, motherboard, CPU, RAM, disks, firmware
      - Every PnP device with its driver, hardware IDs, problem codes and update-search links
      - Windows version, support status, feature-upgrade history, pending reboots
      - Full Windows Update history, with failed updates checked for later resolution/supersedence
      - Optional: what Windows Update currently offers (software + drivers), read-only search
      - Event-log scan for driver/hardware problems, BSODs, GPU resets, storage errors
      - Driver install failures (setupapi.dev.log), CBS servicing errors, upgrade (Panther) logs
    Writes audit.json and an HTML report to the output folder.

.PARAMETER OutputDir
    Where to write the report. Default: Desktop\PCAudit\<computer>_<timestamp>

.PARAMETER EventDays
    How many days of event logs to scan for driver/hardware errors. Default 30.

.PARAMETER CheckWindowsUpdate
    Also ask Windows Update (read-only search) which updates and drivers are currently offered.
    Needs internet; takes 1-5 minutes. Nothing is downloaded or installed.

.PARAMETER DriverAgeYears
    Flag third-party drivers older than this many years. Default 3.

.PARAMETER TemplatePath
    Path to report-template.html. Default: next to this script.

.PARAMETER SkipCatalog
    Skip the per-device Microsoft Update Catalog check (the slowest online step, about 1-2 minutes).

.PARAMETER Offline
    Skip the online lookups (manufacturer BIOS/driver lists, GPU driver versions).

.PARAMETER NoOpen
    Don't open the report in the browser when done.

.EXAMPLE
    .\Invoke-PCAudit.ps1 -CheckWindowsUpdate        (from an elevated PowerShell prompt)
#>
[CmdletBinding()]
param(
    [string]$OutputDir,
    [int]$EventDays = 30,
    [switch]$CheckWindowsUpdate,
    [int]$DriverAgeYears = 3,
    [switch]$Offline,
    [switch]$SkipCatalog,
    [string]$TemplatePath,
    [switch]$NoOpen
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'
$ToolVersion = '0.4.4'
$script:CollectionNotes = New-Object System.Collections.Generic.List[object]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step([string]$Message) { Write-Host "[*] $Message" -ForegroundColor Cyan }

function Add-Note([string]$Section, [string]$Message) {
    $script:CollectionNotes.Add([pscustomobject]@{ Section = $Section; Message = $Message })
    Write-Host "    [!] $Section : $Message" -ForegroundColor Yellow
}

function Invoke-Section([string]$Name, [scriptblock]$Block) {
    Write-Step $Name
    try { & $Block }
    catch { Add-Note $Name $_.Exception.Message }
}

function Format-Date($d) {
    if ($null -eq $d -or $d -eq '') { return $null }
    try { return ([datetime]$d).ToString('yyyy-MM-dd') } catch { return [string]$d }
}
function Format-Time($d) {
    if ($null -eq $d -or $d -eq '') { return $null }
    try { return ([datetime]$d).ToString('yyyy-MM-ddTHH:mm:ss') } catch { return [string]$d }
}
function Format-HResult($h) {
    if ($null -eq $h) { return $null }
    try { $u = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int]$h), 0); return ('0x{0:X8}' -f $u) }
    catch { return [string]$h }
}
# Windows Error Reporting writes Event 1001 when it PROCESSES a report, which can be long after the
# problem (a stuck report queue re-logs the same dump at every boot). Identify each real occurrence
# by its dump file or report ID, and date it by the dump file name when there is one.
function Get-WerOccurrence([string]$msg, $logged) {
    $id = $null; $when = $logged
    $dm = [regex]::Match($msg, '(?i)([A-Z0-9_]+)-(\d{8})-(\d{4})(?:-\d+)?\.dmp')
    if ($dm.Success) {
        $id = $dm.Value.ToUpper()
        try { $when = [datetime]::ParseExact($dm.Groups[2].Value + $dm.Groups[3].Value, 'yyyyMMddHHmm', $null) } catch {}
    } else {
        $mm = [regex]::Match($msg, '(?i)\\Minidump\\(\d{6})-\d+-\d+\.dmp')
        if ($mm.Success) { $id = $mm.Value.ToUpper() }
        elseif ($msg -match '(?i)Report Id:\s*([0-9a-f]{8}-[0-9a-f\-]{27})') { $id = $Matches[1].ToLower() }
    }
    if ($when -gt $logged) { $when = $logged }
    return [pscustomobject]@{ Id = $id; When = $when }
}

function Get-Trimmed([string]$s, [int]$max = 600) {
    if (-not $s) { return $s }
    $s = ($s -replace '\s+', ' ').Trim()
    if ($s.Length -gt $max) { return $s.Substring(0, $max) + '...' }
    return $s
}
function ConvertTo-VersionSafe([string]$v) {
    if (-not $v) { return $null }
    $clean = ($v -replace '[^\d\.]', '').Trim('.')
    $parts = @($clean.Split('.') | Where-Object { $_ -ne '' } | Select-Object -First 4)
    if ($parts.Count -lt 2) { $parts += '0' }
    try { return [version]($parts -join '.') } catch { return $null }
}
function New-SearchUrl([string]$q) { 'https://www.google.com/search?q=' + [uri]::EscapeDataString($q) }
function New-DeviceHuntUrl([string]$type, [string]$ven, [string]$dev) { "https://devicehunt.com/view/type/$type/vendor/$ven/device/$dev" }
function New-CatalogUrl([string]$q) { 'https://www.catalog.update.microsoft.com/Search.aspx?q=' + [uri]::EscapeDataString($q) + '&scol=DateComputed&sdir=desc' }

# Read a (possibly locked, possibly huge) text file; returns the last $MaxBytes as lines.
function Read-SharedTail([string]$Path, [long]$MaxBytes = 8MB) {
    $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite,Delete')
    try {
        if ($fs.Length -gt $MaxBytes) { [void]$fs.Seek(-$MaxBytes, 'End') }
        $sr = New-Object System.IO.StreamReader($fs, $true)
        $text = $sr.ReadToEnd()
        $sr.Close()
        return ($text -split "`r?`n")
    } finally { $fs.Dispose() }
}

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

# ---------------------------------------------------------------------------
# Reference tables
# ---------------------------------------------------------------------------
# PCI / USB vendor IDs (hardware IDs use VEN_xxxx / VID_xxxx)
$VendorIds = @{
    '8086'='Intel'; '8087'='Intel'; '10DE'='NVIDIA'; '1002'='AMD'; '1022'='AMD'; '10EC'='Realtek'; '0BDA'='Realtek'
    '14E4'='Broadcom'; '0A5C'='Broadcom'; '168C'='Qualcomm Atheros'; '0CF3'='Qualcomm Atheros'; '17CB'='Qualcomm'
    '1969'='Qualcomm Atheros (Killer)'; '144D'='Samsung'; '04E8'='Samsung'; '1987'='Phison'; '15B7'='SanDisk / WD'
    '1C5C'='SK hynix'; '2646'='Kingston'; '0951'='Kingston'; '126F'='Silicon Motion'; '1E0F'='KIOXIA'; '1179'='Toshiba'
    '1344'='Micron'; '1B21'='ASMedia'; '174C'='ASMedia'; '1B4B'='Marvell'; '11AB'='Marvell'; '1912'='Renesas'
    '1033'='NEC / Renesas'; '14C3'='MediaTek'; '0E8D'='MediaTek'; '1814'='MediaTek (Ralink)'; '148F'='MediaTek (Ralink)'
    '13D3'='AzureWave'; '1217'='O2 Micro'; '1180'='Ricoh'; '1106'='VIA'; '2109'='VIA Labs'; '1B73'='Fresco Logic'
    '197B'='JMicron'; '152D'='JMicron'; '06CB'='Synaptics'; '138A'='Synaptics (Validity)'; '04F3'='ELAN'
    '27C6'='Goodix'; '0489'='Foxconn'; '046D'='Logitech'; '1532'='Razer'; '045E'='Microsoft'; '1414'='Microsoft'
    '1043'='ASUS'; '0B05'='ASUS'; '1462'='MSI'; '1458'='Gigabyte'; '1849'='ASRock'; '1028'='Dell'; '103C'='HP'
    '17AA'='Lenovo'; '1025'='Acer'; '1D6A'='Aquantia / Marvell'; '1AE9'='Wilocity'; '0781'='SanDisk'; '1058'='WD'
    '1D97'='Shenzhen Longsys'; '1E4B'='MAXIO'; '1CC1'='ADATA'; '1D79'='Transcend'; '1BB1'='Seagate'; '0BC2'='Seagate'
    '05AC'='Apple'; '10B5'='Broadcom (PLX)';
    '2FC6'='Comtrue (USB audio chip)'; '20B1'='XMOS (USB audio chip)'; '262A'='Savitech (USB audio chip)'; '0D8C'='C-Media (USB audio chip)'
    '1B1C'='Corsair'; '1038'='SteelSeries'; '1395'='Sennheiser / EPOS'; '0B0E'='Jabra (GN)'; '047F'='Poly (Plantronics)'
    '05E3'='Genesys Logic (USB hub chip)'; '0424'='Microchip / SMSC (USB hub chip)'; '2357'='TP-Link'; '0B95'='ASIX'; '15AD'='VMware'; '80EE'='VirtualBox'; '1AF4'='Red Hat (VirtIO)'
}

# Chip-vendor driver pages (only vendors that publish generic drivers for end users)
$ChipVendorPages = @{
    'Intel'  = 'https://www.intel.com/content/www/us/en/support/detect.html'
    'NVIDIA' = 'https://www.nvidia.com/en-us/drivers/'
    'AMD'    = 'https://www.amd.com/en/support/download/drivers.html'
}

# System-builder support pages. Generic pages: the serial/model shown in the report is what you enter there.
$OemSupport = @{
    'Dell'      = 'https://www.dell.com/support/home/'
    'HP'        = 'https://support.hp.com/drivers'
    'Lenovo'    = 'https://pcsupport.lenovo.com/'
    'ASUS'      = 'https://www.asus.com/support/download-center/'
    'MSI'       = 'https://www.msi.com/support'
    'Gigabyte'  = 'https://www.gigabyte.com/Support'
    'ASRock'    = 'https://www.asrock.com/support/index.asp'
    'Acer'      = 'https://www.acer.com/support'
    'Microsoft' = 'https://support.microsoft.com/surface'
    'Samsung'   = 'https://www.samsung.com/support/'
    'Dynabook'  = 'https://support.dynabook.com/'
    'Fujitsu'   = 'https://support.ts.fujitsu.com/'
    'Razer'     = 'https://mysupport.razer.com/'
    'Huawei'    = 'https://consumer.huawei.com/en/support/'
    'Medion'    = 'https://www.medion.com/support'
    'Framework' = 'https://knowledgebase.frame.work/'
    'Intel'     = 'https://www.intel.com/content/www/us/en/support.html'
    'Biostar'   = 'https://www.biostar.com.tw/'
    'Supermicro'= 'https://www.supermicro.com/en/support'
}

# Windows end-of-updates dates (Home/Pro, Enterprise/Education). Checked Nov 2026; verify at
# https://learn.microsoft.com/lifecycle/products/windows-11-home-and-pro
$WinLifecycle = @{
    'W11-21H2' = @('2023-10-10','2024-10-08'); 'W11-22H2' = @('2024-10-08','2025-10-14')
    'W11-23H2' = @('2025-11-11','2026-11-10'); 'W11-24H2' = @('2026-10-13','2027-10-12')
    'W11-25H2' = @('2027-10-12',$null);        'W11-26H1' = @('2028-03-14','2029-03-13')
    'W10-22H2' = @('2025-10-14','2025-10-14'); 'W10-21H2' = @('2023-06-13','2024-06-11')
}

# Device Manager problem codes
$ProblemCodes = @{
    1='Device is not configured correctly'; 3='Driver may be corrupted, or system low on memory'; 10='Device cannot start'
    12='Not enough free resources'; 14='Restart required'; 18='Reinstall the drivers'; 19='Registry configuration corrupt'
    21='Windows is removing this device'; 22='Device is disabled'; 24='Device not present / not working / missing drivers'
    28='No driver installed'; 29='Disabled in firmware (BIOS)'; 31='Windows cannot load the driver'
    32='Driver service disabled'; 37='Driver returned failure on init'; 38='Previous driver instance still in memory'
    39='Driver corrupted or missing'; 40='Driver service key missing/invalid'; 41='Driver loaded but device not found'
    43='Device reported a problem (stopped)'; 45='Not currently connected'; 47='Prepared for safe removal'
    48='Driver blocked (known compatibility problem)'; 49='Registry size limit exceeded'; 50='Cannot apply all properties'
    51='Waiting on another device'; 52='Driver signature cannot be verified'; 53='Reserved by kernel debugger'
    54='Failed, undergoing reset'
}

# Bugcheck (BSOD) codes
$BugChecks = @{
    0x0A='IRQL_NOT_LESS_OR_EQUAL'; 0x19='BAD_POOL_HEADER'; 0x1A='MEMORY_MANAGEMENT'; 0x1E='KMODE_EXCEPTION_NOT_HANDLED'
    0x24='NTFS_FILE_SYSTEM'; 0x3B='SYSTEM_SERVICE_EXCEPTION'; 0x50='PAGE_FAULT_IN_NONPAGED_AREA'
    0x77='KERNEL_STACK_INPAGE_ERROR'; 0x7A='KERNEL_DATA_INPAGE_ERROR'; 0x7B='INACCESSIBLE_BOOT_DEVICE'
    0x7E='SYSTEM_THREAD_EXCEPTION_NOT_HANDLED'; 0x7F='UNEXPECTED_KERNEL_MODE_TRAP'; 0x9F='DRIVER_POWER_STATE_FAILURE'
    0xA0='INTERNAL_POWER_ERROR'; 0xC2='BAD_POOL_CALLER'; 0xC4='DRIVER_VERIFIER_DETECTED_VIOLATION'
    0xD1='DRIVER_IRQL_NOT_LESS_OR_EQUAL'; 0xEF='CRITICAL_PROCESS_DIED'; 0xF4='CRITICAL_OBJECT_TERMINATION'
    0xFC='ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY'; 0x101='CLOCK_WATCHDOG_TIMEOUT'; 0x109='CRITICAL_STRUCTURE_CORRUPTION'
    0x10D='WDF_VIOLATION'; 0x116='VIDEO_TDR_FAILURE'; 0x117='VIDEO_TDR_TIMEOUT_DETECTED'; 0x119='VIDEO_SCHEDULER_INTERNAL_ERROR'
    0x124='WHEA_UNCORRECTABLE_ERROR'; 0x133='DPC_WATCHDOG_VIOLATION'; 0x139='KERNEL_SECURITY_CHECK_FAILURE'
    0x13A='KERNEL_MODE_HEAP_CORRUPTION'; 0x154='UNEXPECTED_STORE_EXCEPTION'; 0x15F='CONNECTED_STANDBY_WATCHDOG_TIMEOUT_LIVEDUMP'
    0x1000007E='SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M'; 0x1000008E='KERNEL_MODE_EXCEPTION_NOT_HANDLED_M'
}

# Common Windows Update / servicing error codes
$WuErrors = @{
    '0x80070002'='File not found - often a corrupted update cache (SoftwareDistribution)'
    '0x80070003'='Path not found - update cache or component store problem'
    '0x80070005'='Access denied - permissions, security software or policy interference'
    '0x8007000D'='Invalid data - corrupted download or component store'
    '0x80070020'='File in use by another process - often antivirus'
    '0x80070070'='Not enough disk space'
    '0x800700C1'='Not a valid Win32 application - corrupted file'
    '0x80070422'='Windows Update service is disabled'
    '0x800705B4'='Operation timed out'
    '0x80070643'='Installation failure (generic MSI/installer error; WinRE partition too small for some updates)'
    '0x8007371B'='Component store transaction error - missing/corrupt components'
    '0x80073712'='Component store corrupted - DISM /RestoreHealth usually needed'
    '0x80073701'='Component store: assembly missing - DISM /RestoreHealth usually needed'
    '0x800F081F'='Source files not found - component store corruption'
    '0x800F0831'='Missing prerequisite/baseline package - component store corruption'
    '0x800F0922'='Failed to install - reserved/system partition too small, or VPN/connection to update service'
    '0x800F0988'='Component store cleanup needed / corrupted'
    '0x800F0986'='Servicing failure while staging the update'
    '0x800F0991'='Package not applicable or prerequisite missing'
    '0x80240017'='Update not applicable to this system'
    '0x8024200D'='Update needs to be downloaded again (incomplete download)'
    '0x80242016'='Unexpected post-reboot state - install did not complete'
    '0x80244022'='Update server busy / HTTP 503'
    '0x8024402C'='Proxy or DNS problem reaching update server'
    '0x80246007'='Update not downloaded - BITS problem'
    '0x8024A105'='Download/install interrupted'
    '0xC1900101'='Driver error during feature upgrade (rolled back) - update/remove drivers, check SetupDiag'
    '0xC1900104'='Feature upgrade failed - check Panther logs / SetupDiag'
    '0xC1900200'='Hardware does not meet minimum requirements for this upgrade'
    '0xC1900202'='Hardware does not meet minimum requirements for this upgrade'
    '0xC1900208'='Incompatible app blocking the upgrade'
    '0x80004005'='Unspecified error'
    '0x8000FFFF'='Catastrophic failure / unexpected state - often servicing stack issue'
}

# Known event signatures relevant to drivers/hardware
# Provider is a regex; Ids empty = any id
$EventSignatures = @(
    @{ P='^Microsoft-Windows-Kernel-Power$'; I=@(41); C='Crash / power'; S='high'; H='Unexpected restart without clean shutdown (power loss, hard hang or BSOD). Check BugCheck events and PSU/power.' }
    @{ P='^Microsoft-Windows-WER-SystemErrorReporting$|^BugCheck$'; I=@(1001); C='Crash / power'; S='high'; H='Blue screen (bugcheck). See Crashes section and minidumps.' }
    @{ P='^EventLog$'; I=@(6008); C='Crash / power'; S='medium'; H='Previous shutdown was unexpected.' }
    @{ P='^Microsoft-Windows-WHEA-Logger$'; I=@(); C='Hardware error (WHEA)'; S='high'; H='CPU / memory / PCIe hardware error reported by firmware. Corrected errors repeating = failing part, bad overclock or BIOS issue.' }
    @{ P='^Display$'; I=@(4101); C='Graphics'; S='high'; H='Graphics driver stopped responding and recovered (TDR). Update GPU driver; check temps/power.' }
    @{ P='^nvlddmkm$'; I=@(); C='Graphics'; S='high'; H='NVIDIA kernel driver error. Update/clean-install NVIDIA driver.' }
    @{ P='^(amdkmdag|amdkmdap|amdwddmg|amdkmpfd)$'; I=@(); C='Graphics'; S='high'; H='AMD graphics driver error. Update AMD driver.' }
    @{ P='^(igfx|igfxn|igdkmd64|igdkmdn64|igdkmdnd64)$'; I=@(); C='Graphics'; S='high'; H='Intel graphics driver error. Update Intel graphics driver (OEM or Intel).' }
    @{ P='^disk$'; I=@(7,11,51,52,153,154,157); C='Storage'; S='high'; H='Disk errors: 7 bad block, 11 controller error, 51 paging I/O error, 153 I/O retried, 157 disk surprise-removed. Check drive health/cabling/firmware.' }
    @{ P='^Ntfs$|^Microsoft-Windows-Ntfs$'; I=@(55,98,130,137,140); C='Storage'; S='high'; H='File system problem or corruption. Run chkdsk; check drive health.' }
    @{ P='^(storahci|stornvme|iaStor\w*|iaStorAC|iaStorAVC|iaStorVD|amd_sata|amdsata|amdsbs|nvme\w*|secnvme|samsungnvme\w*)$'; I=@(); C='Storage'; S='high'; H='Storage controller reset/timeout (e.g. id 129). Update chipset/storage driver and SSD firmware; check power settings (ASPM).' }
    @{ P='^volmgr$'; I=@(46,161,162); C='Storage'; S='medium'; H='Crash-dump or volume manager error (dump file could not be written / disk issue).' }
    @{ P='^Microsoft-Windows-Kernel-PnP$'; I=@(); C='Driver load'; S='medium'; H='Plug and Play: a driver failed to load (219) or a device could not start.' }
    @{ P='^Service Control Manager$'; I=@(7000,7009,7011,7026,7038,7043); C='Driver load'; S='medium'; H='A driver or service failed to start (7026 lists boot/system drivers that failed to load).' }
    @{ P='^Service Control Manager$'; I=@(7031,7034,7024,7023,7022); C='Service crash'; S='low'; H='A service crashed or terminated with an error.' }
    @{ P='^(USBXHCI|USBHUB3|UCX01000|usbhub|Microsoft-Windows-USB-USBHUB3|Microsoft-Windows-USB-USBXHCI)$'; I=@(); C='USB'; S='medium'; H='USB controller/hub error. Update chipset/USB drivers; check device/cable/hub power.' }
    @{ P='^(BTHUSB|BTHPORT|BthEnum|ibtusb|RtkBtFilter|BTHMINI|Microsoft-Windows-Bluetooth-.*)$'; I=@(); C='Bluetooth'; S='medium'; H='Bluetooth driver error. Update Bluetooth driver (often paired with the Wi-Fi card vendor).' }
    @{ P='^(Netwtw\d*|Netwbw\d*|NETwNb64|e1\w*express|e1d\w*|e1r\w*|e1i\w*|e2f\w*|rt\d+x64|rtcx\w*|rtwlane\w*|RTWlanE|athw\w*|Qcamain\w*|qcwlan\w*|BCMWL\w*|mtkwl\w*|mrvlpcie\w*|Killer\w*|b57nd60a|L1C\w*|e1c\w*|Microsoft-Windows-WLAN-AutoConfig|Microsoft-Windows-NDIS)$'; I=@(); C='Network'; S='medium'; H='Network adapter driver error / reset. Update Wi-Fi/LAN driver.' }
    @{ P='^ACPI$|^Microsoft-Windows-Kernel-Acpi$'; I=@(); C='Firmware (BIOS/ACPI)'; S='medium'; H='ACPI/firmware error. A BIOS update often fixes these.' }
    @{ P='^Microsoft-Windows-Kernel-Processor-Power$'; I=@(37); C='Firmware (BIOS/ACPI)'; S='low'; H='CPU speed limited by firmware (thermal/power limit). Check cooling, power plan, BIOS.' }
    @{ P='^(i8042prt|HidUsb|hidi2c|HidBth|iaLPSS\w*|SynTP|ETD|SynRMIHID|Microsoft-Windows-Input-HidClass)$'; I=@(); C='Input devices'; S='low'; H='Keyboard/touchpad/HID driver error. Update chipset (serial IO) and touchpad drivers.' }
    @{ P='^(HDAudBus|IntcAzAudAddService|IntcDAud|RTKVHD64|RtkAudUService|Microsoft-Windows-Audio)$'; I=@(); C='Audio'; S='low'; H='Audio driver error. Update audio driver (OEM version preferred for laptops).' }
    @{ P='^Microsoft-Windows-Resource-Exhaustion-Detector$'; I=@(2004); C='System resources'; S='medium'; H='Windows ran low on virtual memory. Possible memory leak (sometimes a driver).' }
    @{ P='^Microsoft-Windows-DistributedCOM$'; I=@(10016,10010,10005); C='Known noise'; S='info'; H='DCOM permission/timeouts: almost always harmless, safe to ignore.' }
    @{ P='^Microsoft-Windows-WindowsUpdateClient$'; I=@(20,25,31); C='Windows Update'; S='medium'; H='Windows Update install/download failure. See Windows Update section.' }
    @{ P='^Microsoft-Windows-TPM-WMI$|^TPM$'; I=@(); C='Firmware (BIOS/ACPI)'; S='low'; H='TPM error. A BIOS/TPM firmware update can fix this.' }
)

# GPU user-mode driver modules appearing in application crashes
$GpuModulesRegex = '(?i)\b(nvwgf2umx\w*|nvoglv\w*|nvd3dum\w*|nvcuda\w*|nvapi\w*|atidxx\w*|aticfx\w*|amdxx\w*|amdxc\w*|atiumd\w*|amdihk\w*|igd10\w*|igd11\w*|igd12\w*|igdumdim\w*|igxelpicd\w*|ig\d+icd\w*|igc64)\.dll'

# Placeholder strings OEMs/board makers leave in SMBIOS on custom builds
$Placeholders = @('', 'System manufacturer', 'System Product Name', 'To Be Filled By O.E.M.', 'To be filled by O.E.M.',
                  'Default string', 'O.E.M.', 'OEM', 'Not Applicable', 'None', 'Unknown', 'System Serial Number',
                  'Type1ProductConfigId', 'All Series', 'Standard PC', 'x.x', 'Rev X.0x', 'Rev 1.xx', 'To be filled by O.E.M', 'Not Specified', 'Base Board Version', 'Base Board Serial Number')

function Get-NormalizedVendor([string]$s) {
    if (-not $s) { return $null }
    switch -Regex ($s) {
        'Dell'                         { return 'Dell' }
        'Hewlett|^HP\b|^HP$|\bHP\b'     { return 'HP' }
        'Lenovo'                       { return 'Lenovo' }
        'ASUS|ASUSTeK'                 { return 'ASUS' }
        'Micro-Star|^MSI\b'            { return 'MSI' }
        'Gigabyte'                     { return 'Gigabyte' }
        'ASRock'                       { return 'ASRock' }
        'Acer'                         { return 'Acer' }
        'Microsoft'                    { return 'Microsoft' }
        'Samsung'                      { return 'Samsung' }
        'Toshiba|Dynabook'             { return 'Dynabook' }
        'Fujitsu'                      { return 'Fujitsu' }
        'Razer'                        { return 'Razer' }
        'Huawei'                       { return 'Huawei' }
        'Medion'                       { return 'Medion' }
        'Framework'                    { return 'Framework' }
        'Biostar'                      { return 'Biostar' }
        'Supermicro'                   { return 'Supermicro' }
        '^Intel'                       { return 'Intel' }
        'VMware|innotek|VirtualBox|QEMU|Xen|Parallels' { return 'Virtual machine' }
    }
    return $s.Trim()
}

function Test-Placeholder([string]$s) {
    if ($null -eq $s) { return $true }
    $t = $s.Trim()
    foreach ($p in $Placeholders) { if ($t -ieq $p) { return $true } }
    return $false
}

# ---------------------------------------------------------------------------
# Output location
# ---------------------------------------------------------------------------
$Started = Get-Date
if (-not $OutputDir) {
    $desk = [Environment]::GetFolderPath('Desktop')
    if (-not $desk) { $desk = $env:TEMP }
    $OutputDir = Join-Path $desk ("PCAudit\{0}_{1}" -f $env:COMPUTERNAME, $Started.ToString('yyyyMMdd_HHmmss'))
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host ''
Write-Host "PC Audit $ToolVersion - read-only scan. Nothing on this PC will be changed." -ForegroundColor Green
if (-not $IsAdmin) {
    Write-Host 'Not running as administrator: some sections (CBS log, disk reliability, Secure Boot, minidumps) will be limited.' -ForegroundColor Yellow
}
Write-Host ''

$script:Audit = [ordered]@{
    Meta = [ordered]@{
        Tool = 'PC Audit'; Version = $ToolVersion; Computer = $env:COMPUTERNAME; User = $env:USERNAME
        IsAdmin = $IsAdmin; Started = Format-Time $Started; EventDays = $EventDays
        CheckWindowsUpdate = [bool]$CheckWindowsUpdate; DriverAgeYears = $DriverAgeYears
        PSVersion = $PSVersionTable.PSVersion.ToString()
    }
}

# ---------------------------------------------------------------------------
# 1. System / BIOS / board
# ---------------------------------------------------------------------------
Invoke-Section 'System, BIOS and motherboard' {
    $cs   = Get-CimInstance Win32_ComputerSystem
    $csp  = Get-CimInstance Win32_ComputerSystemProduct
    $bios = Get-CimInstance Win32_BIOS
    $bb   = Get-CimInstance Win32_BaseBoard
    $encl = Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue | Select-Object -First 1

    $customBuild = (Test-Placeholder $cs.Manufacturer) -or (Test-Placeholder $cs.Model)
    if ($customBuild) {
        $vendor = Get-NormalizedVendor $bb.Manufacturer
        $model  = $bb.Product
        $serial = $bb.SerialNumber
    } else {
        $vendor = Get-NormalizedVendor $cs.Manufacturer
        $model  = $cs.Model
        $serial = $bios.SerialNumber
    }
    $friendly = $model
    if ($vendor -eq 'Lenovo' -and $csp.Version -and -not (Test-Placeholder $csp.Version)) { $friendly = "$($csp.Version) ($($cs.Model))" }

    $chassisTypes = @{3='Desktop';4='Desktop';5='Desktop';6='Mini tower';7='Tower';8='Portable';9='Laptop';10='Notebook';
                      13='All-in-one';14='Sub-notebook';15='Desktop';16='Desktop';30='Tablet';31='Convertible';32='Detachable';35='Mini PC';36='Stick PC'}
    $chassis = $null
    if ($encl -and $encl.ChassisTypes) { $chassis = $chassisTypes[[int]($encl.ChassisTypes[0])] }

    $firmwareType = 'Unknown'; $secureBoot = $null
    try { $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop; $firmwareType = 'UEFI' }
    catch {
        if ($_.Exception.Message -match 'not supported') { $firmwareType = 'Legacy BIOS' }
        elseif ($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception.Message -match 'denied') { $firmwareType = 'UEFI (Secure Boot state needs admin)' }
    }
    if ($firmwareType -eq 'Unknown' -and (Test-Path "$env:windir\Panther\setupact.log")) {
        $line = Select-String -Path "$env:windir\Panther\setupact.log" -Pattern 'Detected boot environment' -SimpleMatch -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($line -match 'EFI') { $firmwareType = 'UEFI' } elseif ($line -match 'BIOS') { $firmwareType = 'Legacy BIOS' }
    }

    $tpm = $null
    try {
        $t = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop
        if ($t) { $tpm = [ordered]@{ Present = $true; Enabled = $t.IsEnabled_InitialValue; SpecVersion = ($t.SpecVersion -split ',')[0]; ManufacturerVersion = $t.ManufacturerVersion } }
    } catch { $tpm = [ordered]@{ Present = $null; Note = 'Needs admin' } }

    $links = New-Object System.Collections.Generic.List[object]
    if ($OemSupport.ContainsKey($vendor)) { $links.Add([pscustomobject]@{ Label = "$vendor support / drivers"; Url = $OemSupport[$vendor] }) }
    if ($vendor -eq 'Dell' -and $serial -and -not (Test-Placeholder $serial)) {
        $links.Add([pscustomobject]@{ Label = "Dell drivers for service tag $serial"; Url = "https://www.dell.com/support/home/product-support/servicetag/$serial/drivers" })
    }
    $links.Add([pscustomobject]@{ Label = 'Web search: model drivers'; Url = (New-SearchUrl "$vendor $model drivers download") })
    $links.Add([pscustomobject]@{ Label = 'Web search: BIOS update'; Url = (New-SearchUrl "$vendor $model BIOS update") })

    $biosAgeDays = $null
    if ($bios.ReleaseDate) { $biosAgeDays = [int]((Get-Date) - [datetime]$bios.ReleaseDate).TotalDays }

    $clean = { param($v) if (Test-Placeholder $v) { $null } else { ([string]$v).Trim() } }
    $serial = & $clean $serial
    $script:Audit.System = [ordered]@{
        Vendor = $vendor; Model = $model; FriendlyModel = $friendly; Serial = $serial
        IsCustomBuild = $customBuild; Chassis = $chassis
        SystemManufacturer = $cs.Manufacturer; SystemModel = $cs.Model; SystemSKU = (& $clean $cs.SystemSKUNumber); SystemFamily = (& $clean $cs.SystemFamily)
        ProductVersion = (& $clean $csp.Version); UUID = $csp.UUID
        Board = [ordered]@{ Manufacturer = $bb.Manufacturer; Product = ([string]$bb.Product).Trim(); Version = (& $clean $bb.Version); Serial = (& $clean $bb.SerialNumber) }
        BIOS = [ordered]@{ Vendor = $bios.Manufacturer; Version = $bios.SMBIOSBIOSVersion; ReleaseDate = Format-Date $bios.ReleaseDate
                           AgeDays = $biosAgeDays; SMBIOS = "$($bios.SMBIOSMajorVersion).$($bios.SMBIOSMinorVersion)"
                           FirmwareType = $firmwareType; SecureBoot = $secureBoot }
        TPM = $tpm
        MemoryGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        SupportLinks = $links.ToArray()
    }
}

# ---------------------------------------------------------------------------
# 2. CPU / RAM / GPU / disks
# ---------------------------------------------------------------------------
Invoke-Section 'CPU, memory, graphics and disks' {
    $cpus = @(Get-CimInstance Win32_Processor | ForEach-Object {
        [ordered]@{ Name = ($_.Name -replace '\s+',' ').Trim(); Manufacturer = $_.Manufacturer; Cores = $_.NumberOfCores
                    Threads = $_.NumberOfLogicalProcessors; MaxMHz = $_.MaxClockSpeed; Microcode = $null }
    })
    try {
        $mc = (Get-ItemProperty 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0' -ErrorAction Stop).'Update Revision'
        if ($mc -and $mc.Length -ge 8 -and $cpus.Count -gt 0) { $cpus[0].Microcode = ('0x{0:X}' -f [BitConverter]::ToUInt32([byte[]]$mc, 4)) }
    } catch {}

    $ram = @(Get-CimInstance Win32_PhysicalMemory | ForEach-Object {
        [ordered]@{ Slot = $_.DeviceLocator; Manufacturer = ($_.Manufacturer -as [string]).Trim(); PartNumber = ($_.PartNumber -as [string]).Trim()
                    CapacityGB = [math]::Round($_.Capacity / 1GB, 1); SpeedMTs = $_.Speed; ConfiguredMTs = $_.ConfiguredClockSpeed }
    })

    $gpus = @(Get-CimInstance Win32_VideoController | ForEach-Object {
        [ordered]@{ Name = $_.Name; DriverVersion = $_.DriverVersion; DriverDate = Format-Date $_.DriverDate
                    PNPDeviceID = $_.PNPDeviceID; Status = $_.Status; Resolution = if ($_.CurrentHorizontalResolution) { "$($_.CurrentHorizontalResolution)x$($_.CurrentVerticalResolution)" } else { $null } }
    })

    $disks = @()
    try {
        $disks = @(Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {
            $d = $_
            $rel = $null
            if ($IsAdmin) {
                try {
                    $r = $d | Get-StorageReliabilityCounter -ErrorAction Stop
                    $rel = [ordered]@{ TemperatureC = $r.Temperature; WearPercent = $r.Wear; PowerOnHours = $r.PowerOnHours
                                       ReadErrorsUncorrected = $r.ReadErrorsUncorrected; WriteErrorsUncorrected = $r.WriteErrorsUncorrected }
                } catch {}
            }
            [ordered]@{ Name = $d.FriendlyName; Model = $d.Model; Serial = ($d.SerialNumber -as [string]).Trim(); MediaType = [string]$d.MediaType
                        BusType = [string]$d.BusType; SizeGB = [math]::Round($d.Size / 1GB, 0); Firmware = $d.FirmwareVersion
                        Health = [string]$d.HealthStatus; OperationalStatus = (@($d.OperationalStatus) -join ', ')
                        Reliability = $rel
                        Links = @([pscustomobject]@{ Label = 'Firmware search'; Url = (New-SearchUrl "$($d.FriendlyName) SSD firmware update") }) }
        })
    } catch { Add-Note 'Disks' "Get-PhysicalDisk unavailable: $($_.Exception.Message)" }

    $volumes = @(Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | ForEach-Object {
        [ordered]@{ Drive = $_.DeviceID; Label = $_.VolumeName; FileSystem = $_.FileSystem
                    SizeGB = [math]::Round($_.Size / 1GB, 1); FreeGB = [math]::Round($_.FreeSpace / 1GB, 1)
                    FreePct = if ($_.Size) { [math]::Round(100 * $_.FreeSpace / $_.Size, 0) } else { $null } }
    })

    $script:Audit.Hardware = [ordered]@{ CPU = $cpus; Memory = $ram; GPU = $gpus; Disks = $disks; Volumes = $volumes }
}

# ---------------------------------------------------------------------------
# 3. Devices and drivers
# ---------------------------------------------------------------------------
function Get-IdParts([string[]]$ids) {
    $r = [ordered]@{ Bus = $null; Ven = $null; Dev = $null; SubSys = $null; SubVendor = $null; Rev = $null; Codec = $null; Best = $null; Chip = $null }
    if (-not $ids -or $ids.Count -eq 0) { return $r }
    $first = $ids[0]
    $r.Bus = ($first -split '\\')[0]
    $r.Best = $first -replace '(?i)&REV_[0-9A-F]+', ''
    foreach ($id in $ids) {
        if (-not $r.Ven) {
            if ($id -match '(?i)VEN_([0-9A-F]{4})') { $r.Ven = $Matches[1].ToUpper() }
            elseif ($id -match '(?i)(?:^|[\\&])VID_?([0-9A-F]{4})(?![0-9A-F])') { $r.Ven = $Matches[1].ToUpper() }
        }
        if (-not $r.Dev) {
            if ($id -match '(?i)DEV_([0-9A-F]{4})') { $r.Dev = $Matches[1].ToUpper() }
            elseif ($id -match '(?i)(?:^|[\\&])PID_?([0-9A-F]{4})(?![0-9A-F])') { $r.Dev = $Matches[1].ToUpper() }
        }
        if (-not $r.SubSys -and $id -match '(?i)SUBSYS_([0-9A-F]{8})') {
            $r.SubSys = $Matches[1].ToUpper()
            # PCI: SUBSYS_<device><vendor>; HD Audio: SUBSYS_<vendor><device>
            if ($r.Bus -match '^(HDAUDIO|INTELAUDIO)$') { $r.SubVendor = $r.SubSys.Substring(0, 4) } else { $r.SubVendor = $r.SubSys.Substring(4, 4) }
        }
        if (-not $r.Rev -and $id -match '(?i)REV_([0-9A-F]{2,4})') { $r.Rev = $Matches[1].ToUpper() }
    }
    switch -Regex ($r.Bus) {
        '^PCI$'           { if ($r.Ven -and $r.Dev) { $r.Chip = "PCI\VEN_$($r.Ven)&DEV_$($r.Dev)" } }
        '^USB$'           { if ($r.Ven -and $r.Dev) { $r.Chip = "USB\VID_$($r.Ven)&PID_$($r.Dev)" } }
        '^(HDAUDIO|INTELAUDIO)$' { $r.Chip = $r.Best -replace '(?i)&SUBSYS_[0-9A-F]+', ''; if ($r.Ven -and $r.Dev) { $r.Codec = "$($r.Ven):$($r.Dev)" } }
        default           { $r.Chip = $first }
    }
    return $r
}

Invoke-Section 'Devices and drivers' {
    $entities = @(Get-CimInstance Win32_PnPEntity)
    $entById = @{}
    foreach ($e in $entities) { if ($e.PNPDeviceID) { $entById[$e.PNPDeviceID.ToUpper()] = $e } }
    $signed = @(Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.DeviceID })
    $signedById = @{}
    foreach ($s in $signed) { $signedById[$s.DeviceID.ToUpper()] = $s }

    $hardwareBuses = '^(PCI|USB|HDAUDIO|INTELAUDIO|ACPI|UEFI|SCSI|NVME|DISPLAY|HID|BTHENUM|BTH|BTHLE|BTHLEDEVICE|SD|MMC|IDE|STORAGE|USB4|TBT)$'
    $hideClasses = '^(Volume|VolumeSnapshot|LegacyDriver|SoftwareDevice|SoftwareComponent|Processor|Computer|Printer|PrintQueue|WPD|SmartCardFilter|NetService|NetClient|NetTrans)$'
    $now = Get-Date
    $devices = New-Object System.Collections.Generic.List[object]

    $allIds = @($entById.Keys) + @($signedById.Keys | Where-Object { -not $entById.ContainsKey($_) })
    foreach ($id in $allIds) {
        $e = $entById[$id]; $s = $signedById[$id]
        $hwids = @()
        if ($e -and $e.HardwareID) { $hwids = @($e.HardwareID) } elseif ($s -and $s.HardWareID) { $hwids = @($s.HardWareID) }
        $compat = @(); if ($e -and $e.CompatibleID) { $compat = @($e.CompatibleID) }
        $parts = Get-IdParts $hwids
        $bus = ($id -split '\\')[0]

        $name     = if ($e -and $e.Name) { $e.Name } elseif ($s) { $s.DeviceName } else { $id }
        $class    = if ($e -and $e.PNPClass) { $e.PNPClass } elseif ($s) { $s.DeviceClass } else { $null }
        $errCode  = if ($e) { [int]$e.ConfigManagerErrorCode } else { $null }
        $present  = if ($e -and $null -ne $e.Present) { [bool]$e.Present } else { [bool]$e }
        $provider = if ($s) { $s.DriverProviderName } else { $null }
        $drvDate  = if ($s -and $s.DriverDate) { [datetime]$s.DriverDate } else { $null }
        $isHw     = ($bus -match $hardwareBuses) -and -not ($class -match $hideClasses)
        if ($class -eq 'Firmware') { $isHw = $true }

        $flags = New-Object System.Collections.Generic.List[string]
        $problem = $null
        if ($errCode -and $errCode -ne 0 -and $errCode -ne 45) {
            $problem = "Code $errCode - " + $(if ($ProblemCodes.ContainsKey($errCode)) { $ProblemCodes[$errCode] } else { 'Unknown problem' })
            if ($errCode -eq 22) { $flags.Add('Disabled') } else { $flags.Add('Problem') }
        }
        if ($isHw -and -not $s -and $present -and $class -ne 'Firmware') { $flags.Add('NoDriver') }
        if ($s -and $s.IsSigned -eq $false) { $flags.Add('Unsigned') }
        $isMsDriver = $provider -match '^Microsoft'
        if ($isHw -and $isMsDriver -and $bus -match '^(PCI|HDAUDIO|INTELAUDIO|USB)$') {
            # Generic inbox driver on hardware that usually benefits from a vendor driver
            if (($class -eq 'Display') -or ($name -match 'Basic Display|Basic Render') -or
                ($class -eq 'MEDIA' -and $bus -match 'HDAUDIO|INTELAUDIO' -and $name -match 'High Definition Audio Device') -or
                ($class -eq 'Net' -and $bus -eq 'PCI') -or
                ($class -eq 'System' -and $name -match 'PCI Simple Communications|SM Bus Controller|PCI Data Acquisition|PCI Encryption')) {
                $flags.Add('GenericDriver')
            }
        }
        $ageYears = $null
        if ($drvDate) { $ageYears = [math]::Round((($now - $drvDate).TotalDays / 365.25), 1) }
        # Driver age only matters for internal parts (chipset, graphics, network, storage, audio codec, Bluetooth).
        # External USB peripherals (DACs, headsets, mice, keyboards, printers...) often keep the same driver for years.
        $isPeripheral = ($bus -match '^(USB|HID|BTHENUM|BTHLE|BTHLEDEVICE|SWD)$') -and ($class -notmatch '^(Bluetooth|Net)$')
        if ($isHw -and $drvDate -and -not $isMsDriver -and -not $isPeripheral -and $ageYears -ge $DriverAgeYears) { $flags.Add('OldDriver') }
        if (-not $present) { $flags.Add('NotPresent') }

        $chipVendor = if ($parts.Ven) { $VendorIds[$parts.Ven] } else { $null }
        $subVendor  = if ($parts.SubVendor) { $VendorIds[$parts.SubVendor] } else { $null }

        # --- Which devices can realistically have a driver in the Microsoft Update Catalog ---
        # The Catalog only holds vendor-submitted drivers, indexed by hardware ID. Devices running on
        # Windows' own class drivers (HID interfaces, mice/keyboards, disks, USB hubs/composite parents,
        # monitors, generic ACPI PNPxxxx objects) never appear there, so searching them always returns nothing.
        $isChildIf   = $id -match '(?i)&MI_[0-9A-F]{2}' -or $id -match '(?i)&COL[0-9A-F]{2}'
        $needsDriver = ($flags -contains 'Problem') -or ($flags -contains 'NoDriver') -or ($flags -contains 'GenericDriver')
        $catalogNote = $null
        $isRootHub   = $id -match '(?i)^USB\\ROOT_HUB'
        $catalogOk   = $isHw -and $parts.Best -and $bus -match '^(PCI|HDAUDIO|INTELAUDIO|ACPI|USB|USB4|BTH|SD|UEFI)$' -and -not $isRootHub
        if ($catalogOk -and $bus -eq 'ACPI' -and $id -match '(?i)^ACPI\\(PNP|ACPI|FIXEDBUTTON|GENUINEINTEL|AUTHENTICAMD|THERMALZONE|MSFT|VEN_)') { $catalogOk = $false }
        if ($catalogOk -and $isMsDriver -and -not $needsDriver -and
            (($class -match '^(USB|HIDClass|Keyboard|Mouse|DiskDrive|Monitor|SCSIAdapter|Ports|System|Battery|Net)$' -and $bus -ne 'PCI') -or $isChildIf)) {
            $catalogOk = $false
        }
        if ($isHw -and -not $catalogOk) {
            if ($bus -match '^(HID|BTHENUM|BTHLE|BTHLEDEVICE|SWD|ROOT)$' -or $isChildIf) {
                $catalogNote = 'Sub-device (interface) of another device using a built-in Windows driver - update the parent device or the maker''s own software instead.'
            } elseif ($isMsDriver) {
                $catalogNote = 'Uses a built-in Windows class driver - no separate driver is published in the Microsoft Catalog for this ID.'
            }
        }

        # Search terms: Catalog matches tokens, so give an exact (bus+IDs+subsystem) and a broad (vendor+device only) form
        $broad = $null
        switch -Regex ($bus) {
            '^PCI$'                  { if ($parts.Ven -and $parts.Dev) { $broad = "VEN_$($parts.Ven)&DEV_$($parts.Dev)" } }
            '^(HDAUDIO|INTELAUDIO)$' { if ($parts.Ven -and $parts.Dev) { $broad = "VEN_$($parts.Ven)&DEV_$($parts.Dev)" } }
            '^(USB|USB4|BTH)$'       { if ($parts.Ven -and $parts.Dev) { $broad = "VID_$($parts.Ven)&PID_$($parts.Dev)" } }
            '^ACPI$'                 { $short = $hwids | Where-Object { $_ -match '(?i)^ACPI\\(?!VEN_)[^\\&]+$' } | Select-Object -First 1
                                       $broad = if ($short) { $short } else { $parts.Best } }
        }

        $links = New-Object System.Collections.Generic.List[object]
        if ($catalogOk) {
            if ($parts.Best -match '(?i)SUBSYS_') {
                $links.Add([pscustomobject]@{ Label = 'Catalog: this board'; Url = (New-CatalogUrl $parts.Best) })
            }
            if ($broad) { $links.Add([pscustomobject]@{ Label = 'Catalog: same chip, any maker'; Url = (New-CatalogUrl $broad) }) }
            elseif ($parts.SubSys -eq $null) { $links.Add([pscustomobject]@{ Label = 'Catalog search'; Url = (New-CatalogUrl $parts.Best) }) }
        }
        if ($chipVendor -and $ChipVendorPages.ContainsKey($chipVendor) -and $isHw -and $bus -match '^(PCI|HDAUDIO|INTELAUDIO|USB|ACPI)$') {
            $links.Add([pscustomobject]@{ Label = "$chipVendor drivers"; Url = $ChipVendorPages[$chipVendor] })
        }
        if ($isHw) {
            # A descriptive device name ("HIFIMAN-EF500") searches best on its own; raw IDs only help when the name is generic.
            $cleanName = ($name -replace '\(R\)|\(TM\)|®|™', '' -replace '(?<=[A-Za-z])[-_](?=[A-Za-z0-9])', ' ' -replace '\s+', ' ').Trim()
            $genericName = $name -match '(?i)^(USB|HID|Generic|Standard|Unknown|Composite|PCI|SM Bus|Base System|Multimedia|Audio Device|Speakers|Headphones|Microphone|Line|Digital|High Definition Audio|Bluetooth Device|Ethernet|Network|Controller|Device)\b' -or
                           $name -match '(?i)(Composite Device|Input Device|Root Hub|Generic.*Hub|vendor-defined|compliant)'
            $idQuery = if ($bus -eq 'ACPI' -and $broad) { ($broad -split '\\')[-1] }
                       elseif ($parts.Ven -and $parts.Dev -and $bus -match '^(USB|HID|USB4|BTH)') { "VID_$($parts.Ven)&PID_$($parts.Dev)" }
                       elseif ($parts.Ven -and $parts.Dev) { "VEN_$($parts.Ven)&DEV_$($parts.Dev)" } else { '' }
            if ($isRootHub -and $parts.Ven -and $parts.Dev) {
                # Root hub IDs carry the USB host controller's PCI vendor/device - that controller is what to update
                $ctrl = "VEN_$($parts.Ven)&DEV_$($parts.Dev)"
                $idQuery = $ctrl
                $links.Add([pscustomobject]@{ Label = 'Catalog: USB controller'; Url = (New-CatalogUrl $ctrl) })
                $vn = if ($chipVendor) { ($chipVendor -split ' ')[0] } else { '' }
                $links.Add([pscustomobject]@{ Label = 'Web search'; Url = (New-SearchUrl "$vn USB xHCI controller $ctrl driver".Trim()) })
                if ($true) {
                    $catalogNote = "Root hub of the $(if ($chipVendor) { "$chipVendor " })USB controller (PCI\$ctrl). It uses Windows' built-in driver; problems here usually come from the controller: update the chipset driver and BIOS, check USB power settings (selective suspend) and unplug the devices on these ports to find a faulty one."
                }
            } elseif (-not $genericName) {
                $links.Add([pscustomobject]@{ Label = 'Web search'; Url = (New-SearchUrl "$cleanName driver download") })
            } elseif (($catalogOk -or $needsDriver) -and $idQuery) {
                $links.Add([pscustomobject]@{ Label = 'Web search'; Url = (New-SearchUrl "$idQuery driver") })
            } elseif ($catalogOk -or $needsDriver) {
                $links.Add([pscustomobject]@{ Label = 'Web search'; Url = (New-SearchUrl "$cleanName driver") })
            }
            if ($errCode -and $errCode -notin @(0, 22, 45)) {
                $vn = if ($chipVendor) { ($chipVendor -split ' ')[0] + ' ' } else { '' }
                $links.Add([pscustomobject]@{ Label = "Search this error (code $errCode)"; Url = (New-SearchUrl "`"$cleanName`" $vn`"code $errCode`" Windows") })
            }
            if ($idQuery -and ($genericName -or $needsDriver -or $isRootHub)) {
                # DeviceHunt names the exact chip behind a vendor/device ID; Google finds driver pages for the ID
                $dhType = if ($bus -eq 'PCI' -or $isRootHub) { 'pci' } elseif ($bus -match '^(USB|HID|USB4|BTH)$') { 'usb' } else { $null }
                if ($dhType -and $parts.Ven -and $parts.Dev) {
                    $links.Add([pscustomobject]@{ Label = 'Identify chip (DeviceHunt)'; Url = (New-DeviceHuntUrl $dhType $parts.Ven $parts.Dev) })
                }
                $links.Add([pscustomobject]@{ Label = 'Search hardware ID'; Url = (New-SearchUrl "`"$idQuery`"") })
            }
            if (-not $catalogNote -and $bus -eq 'USB' -and $class -match '^(MEDIA|AudioEndpoint)$') {
                $catalogNote = 'USB audio devices normally work with Windows'' built-in USB Audio driver. A maker driver (often for ASIO / high sample rates) is optional - check the maker''s support page.'
            }
        }

        $devices.Add([pscustomobject][ordered]@{
            Name = $name; Class = $class; Bus = $bus; IsHardware = $isHw; Present = $present
            DeviceManufacturer = if ($e) { $e.Manufacturer } elseif ($s) { $s.Manufacturer } else { $null }
            ChipVendor = $chipVendor; BoardVendorFromSubsys = $subVendor
            Provider = $provider; Version = if ($s) { $s.DriverVersion } else { $null }
            Date = Format-Date $drvDate; AgeYears = $ageYears
            Inf = if ($s) { $s.InfName } else { $null }; Signer = if ($s) { $s.Signer } else { $null }
            Service = if ($e) { $e.Service } else { $null }
            Status = if ($e) { $e.Status } else { $null }; ErrorCode = $errCode; Problem = $problem
            Flags = $flags.ToArray(); InstanceId = $id; HardwareIds = $hwids; CompatibleIds = $compat
            ChipId = $parts.Chip; SubSys = $parts.SubSys; Links = $links.ToArray(); CatalogNote = $catalogNote
            CatalogQuery = $(if ($catalogOk) { $broad } else { $null }); CatalogExactQuery = $(if ($catalogOk -and $parts.Best -match '(?i)SUBSYS_') { $parts.Best } else { $null })
            Catalog = $null
        })
    }
    $script:Audit.Devices = @($devices | Sort-Object @{e={ -not $_.IsHardware }}, Class, Name)
    $script:DeviceList = $devices
}

# ---------------------------------------------------------------------------
# 4. Windows version, lifecycle, upgrades, pending reboot
# ---------------------------------------------------------------------------
Invoke-Section 'Windows version and upgrade history' {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = [int]$cv.CurrentBuildNumber
    $isW11 = $build -ge 22000
    $productName = [string]$cv.ProductName
    if ($isW11) { $productName = $productName -replace 'Windows 10', 'Windows 11' }
    $disp = if ($cv.DisplayVersion) { [string]$cv.DisplayVersion } else { [string]$cv.ReleaseId }
    if ($disp -eq '2009') { $disp = '20H2' }
    $edition = [string]$cv.EditionID
    $isEnterprise = $edition -match 'Enterprise|Education|IoT'
    $isLtsc = $edition -match 'LTSC|LTSB' -or $productName -match 'LTSC|LTSB'

    $key = "$(if ($isW11) { 'W11' } else { 'W10' })-$disp"
    $endDate = $null
    if ($WinLifecycle.ContainsKey($key)) { $endDate = $WinLifecycle[$key][$(if ($isEnterprise) { 1 } else { 0 })] }
    $supportState = 'Unknown - check Microsoft lifecycle page'
    if ($isLtsc) { $supportState = 'LTSC/LTSB edition - check its own lifecycle date' }
    elseif ($endDate) {
        if ((Get-Date) -gt [datetime]$endDate) {
            $supportState = "OUT OF SUPPORT since $endDate"
            if (-not $isW11) { $supportState += ' (unless enrolled in Extended Security Updates)' }
        } else { $supportState = "Supported until $endDate" }
    }

    $installDate = $null
    try { $installDate = Format-Date ([DateTimeOffset]::FromUnixTimeSeconds([int64]$cv.InstallDate).LocalDateTime) } catch {}

    $upgrades = @()
    try {
        $upgrades = @(Get-ChildItem 'HKLM:\SYSTEM\Setup' -ErrorAction Stop | Where-Object { $_.PSChildName -like 'Source OS*' } | ForEach-Object {
            $p = Get-ItemProperty $_.PSPath
            $b = [int]$p.CurrentBuildNumber
            $pn = [string]$p.ProductName; if ($b -ge 22000) { $pn = $pn -replace 'Windows 10','Windows 11' }
            $inst = $null; try { $inst = Format-Date ([DateTimeOffset]::FromUnixTimeSeconds([int64]$p.InstallDate).LocalDateTime) } catch {}
            $replaced = $null; if ($_.PSChildName -match '\(Updated on (.+)\)') { $replaced = $Matches[1] }
            [ordered]@{ Product = $pn; Version = $(if ($p.DisplayVersion) { $p.DisplayVersion } else { $p.ReleaseId })
                        Build = "$($p.CurrentBuildNumber).$($p.UBR)"; InstalledOn = $inst; ReplacedOn = $replaced }
        } | Sort-Object { $_.Build })
    } catch {}

    $pending = New-Object System.Collections.Generic.List[string]
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending.Add('Component Based Servicing (Windows updates/features)') }
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending.Add('Windows Update') }
    $lastBoot = $null; $uptimeH = $null
    try { $os = Get-CimInstance Win32_OperatingSystem; $lastBoot = Format-Time $os.LastBootUpTime; $uptimeH = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 1) } catch {}

    # PendingFileRenameOperations: file moves/deletes Windows does at the next boot. Many programs park temp-file
    # deletions here, and some re-add entries after every boot, so its mere presence is a poor "restart needed" signal.
    # Only real file replacements count, and not if the same entries were already there before the last restart.
    $pfro = @((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations)
    $renames = New-Object System.Collections.Generic.List[object]
    $cleanRx = '(?i)\\(Temp|Tmp)\\|\\AppData\\Local\\Temp\\|\\Config\.Msi\\|\\SoftwareDistribution\\Download\\|\\WinSxS\\Temp\\|\.(tmp|rbf|old|bak|log)$|\\~[^\\]*$|\\[^\\]*\.tmp\\'
    for ($i = 0; $i -lt $pfro.Count; $i += 2) {
        $from = ([string]$pfro[$i]) -replace '^\\\?\?\\', ''
        if (-not $from) { continue }
        $to = if ($i + 1 -lt $pfro.Count) { ([string]$pfro[$i + 1]) -replace '^!?\\\?\?\\', '' } else { '' }
        $action = if ($to) { 'Replace' } else { 'Delete' }
        $cleanup = ($action -eq 'Delete') -or ($from -match $cleanRx -and $to -match $cleanRx)
        $folder = Split-Path $(if ($to) { $to } else { $from }) -Parent
        $renames.Add([pscustomobject][ordered]@{ Action = $action; From = $from; To = $(if ($to) { $to } else { $null }); Folder = $folder; Cleanup = $cleanup })
    }
    $renameState = $null
    if ($renames.Count) {
        $real = @($renames | Where-Object { -not $_.Cleanup })
        # Same entries as the previous scan, with a restart in between? Then a program is re-adding them.
        $survived = $false
        try {
            $root = Split-Path $OutputDir -Parent
            $prevDir = Get-ChildItem -LiteralPath $root -Directory -Filter ("{0}_*" -f $env:COMPUTERNAME) -ErrorAction SilentlyContinue |
                       Where-Object { $_.FullName -ne (Resolve-Path -LiteralPath $OutputDir).Path -and (Test-Path -LiteralPath (Join-Path $_.FullName 'audit.json')) } |
                       Sort-Object LastWriteTime -Descending | Select-Object -First 1
            if ($prevDir) {
                $pw = (Get-Content -LiteralPath (Join-Path $prevDir.FullName 'audit.json') -Raw -Encoding UTF8 | ConvertFrom-Json).Windows
                $prevSet = @($pw.PendingFileRenames | ForEach-Object { "$($_.From)>$($_.To)" })
                $nowSet = @($renames | ForEach-Object { "$($_.From)>$($_.To)" })
                $same = @($nowSet | Where-Object { $prevSet -contains $_ }).Count
                if ($same -gt 0 -and $same -ge [math]::Ceiling($nowSet.Count / 2) -and $pw.LastBoot -and $lastBoot -and (Format-Time $pw.LastBoot) -ne $lastBoot) { $survived = $true }
            }
        } catch {}
        if ($survived) { $renameState = 'Re-added after restart' }
        elseif ($real.Count) { $renameState = 'Restart needed'; $pending.Add("Files waiting to be replaced at restart ($($real.Count))") }
        else { $renameState = 'Cleanup only' }
    }

    $wuPolicy = [ordered]@{}
    $pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -ErrorAction SilentlyContinue
    if ($pol) {
        if ($pol.WUServer) { $wuPolicy.WSUSServer = $pol.WUServer }
        if ($null -ne $pol.ExcludeWUDriversInQualityUpdate) { $wuPolicy.ExcludeDriversFromWU = [bool]$pol.ExcludeWUDriversInQualityUpdate }
        if ($pol.TargetReleaseVersionInfo) { $wuPolicy.TargetReleaseVersion = $pol.TargetReleaseVersionInfo }
    }
    $au = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction SilentlyContinue
    if ($au -and $null -ne $au.NoAutoUpdate) { $wuPolicy.AutomaticUpdatesDisabled = [bool]$au.NoAutoUpdate }
    $dsp = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' -ErrorAction SilentlyContinue
    if ($dsp -and $null -ne $dsp.SearchOrderConfig) { $wuPolicy.DriverSearchFromWU = ($dsp.SearchOrderConfig -ne 0) }
    $wuSvc = Get-Service wuauserv -ErrorAction SilentlyContinue
    if ($wuSvc) { $wuPolicy.WUServiceStartType = [string]$wuSvc.StartType }

    $script:Audit.Windows = [ordered]@{
        Product = $productName; Edition = $edition; Version = $disp; Build = $build; UBR = [int]$cv.UBR
        FullBuild = "$build.$($cv.UBR)"; IsWindows11 = $isW11; Architecture = $env:PROCESSOR_ARCHITECTURE
        InstallDate = $installDate; LastBoot = $lastBoot; UptimeHours = $uptimeH
        SupportEnds = $endDate; SupportState = $supportState
        UpgradeHistory = $upgrades; PendingReboot = $pending.ToArray(); UpdatePolicy = $wuPolicy
        PendingFileRenames = $renames.ToArray(); PendingFileRenameState = $renameState
    }
    $script:CurrentBuild = $build; $script:CurrentUBR = [int]$cv.UBR; $script:CurrentDisplayVersion = $disp
}

# ---------------------------------------------------------------------------
# 5. Windows Update history + resolution analysis
# ---------------------------------------------------------------------------
function Get-UpdateCategory([string]$title) {
    if ($title -match '(?i)\.NET') { return '.NET' }
    if ($title -match '(?i)Feature update|^\s*Windows 1[01],? version \w+\s*$|Upgrade to Windows 1[01]') { return 'Feature update' }
    if ($title -match '(?i)Cumulative Update (Preview )?for Windows|Security Update for Windows|Security Monthly Quality Rollup|Monthly Rollup') { return 'Cumulative update' }
    if ($title -match '(?i)Servicing Stack') { return 'Servicing stack' }
    if ($title -match '(?i)Security Intelligence|Definition Update|KB2267602|antimalware platform|Defender') { return 'Defender' }
    if ($title -match '(?i)Malicious Software Removal') { return 'MSRT' }
    if ($title -match '(?i)Safe OS Dynamic|Setup Dynamic|Windows Recovery Environment|WinRE') { return 'WinRE / Safe OS' }
    if ($title -match '(?i)Microsoft Edge|Office|Microsoft 365|Teams|Visual C\+\+|Silverlight') { return 'Microsoft app' }
    if ($title -match '^\s*[^-]+ - [^-]+ - .+$' -and $title -notmatch 'KB\d{6,}') { return 'Driver / firmware' }
    if ($title -match '(?i)Firmware|BIOS|UEFI') { return 'Driver / firmware' }
    return 'Other'
}

Invoke-Section 'Windows Update history' {
    $entries = New-Object System.Collections.Generic.List[object]
    $session = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    $total = $searcher.GetTotalHistoryCount()
    if ($total -gt 0) {
        $hist = $searcher.QueryHistory(0, $total)
        foreach ($h in $hist) {
            if (-not $h.Title) { continue }
            $title = [string]$h.Title
            $kb = $null; if ($title -match 'KB(\d{6,8})') { $kb = "KB$($Matches[1])" }
            $ym = $null; if ($title -match '^(\d{4})-(\d{2})') { $ym = "$($Matches[1])-$($Matches[2])" }
            $result = switch ([int]$h.ResultCode) { 0 {'Not started'} 1 {'In progress'} 2 {'Succeeded'} 3 {'Succeeded with errors'} 4 {'Failed'} 5 {'Aborted'} default {'Unknown'} }
            $op = switch ([int]$h.Operation) { 1 {'Install'} 2 {'Uninstall'} 3 {'Other'} default {'Unknown'} }
            $hr = Format-HResult $h.HResult
            $local = $null; try { $local = ([datetime]$h.Date).ToLocalTime() } catch {}
            $drvVendor = $null; $drvClass = $null; $drvVer = $null
            if ($title -match '^\s*(.+?) - (.+?) - (.+?)\s*$' -and -not $kb) { $drvVendor = $Matches[1].Trim(); $drvClass = $Matches[2].Trim(); $drvVer = $Matches[3].Trim() }
            $entries.Add([pscustomobject][ordered]@{
                Date = Format-Time $local; DateObj = $local; Title = $title; KB = $kb; YearMonth = $ym
                Category = Get-UpdateCategory $title; Operation = $op; Result = $result; HResult = $hr
                ErrorMeaning = if ($hr -and $WuErrors.ContainsKey($hr)) { $WuErrors[$hr] } else { $null }
                Client = [string]$h.ClientApplicationID; DriverVendor = $drvVendor; DriverClass = $drvClass; DriverVersion = $drvVer
                Resolution = $null; ResolutionDetail = $null; FailCount = $null
            })
        }
    }

    # Installed hotfixes (Win32_QuickFixEngineering) for cross-check
    $hotfixes = @()
    try { $hotfixes = @(Get-CimInstance Win32_QuickFixEngineering -ErrorAction Stop | ForEach-Object { [ordered]@{ KB = $_.HotFixID; Description = $_.Description; InstalledOn = Format-Date $_.InstalledOn } }) } catch {}
    $installedKbs = @{}; foreach ($hf in $hotfixes) { if ($hf.KB) { $installedKbs[$hf.KB.ToUpper()] = $true } }

    $successes = @($entries | Where-Object { $_.Result -like 'Succeeded*' -and $_.Operation -eq 'Install' })
    $failures  = @($entries | Where-Object { $_.Result -in @('Failed','Aborted') })
    $earliest = ($entries | Where-Object DateObj | Sort-Object DateObj | Select-Object -First 1).DateObj

    # Failure counts per KB/title
    $failGroups = @{}
    foreach ($f in $failures) { $k = if ($f.KB) { $f.KB } else { $f.Title }; if (-not $failGroups.ContainsKey($k)) { $failGroups[$k] = 0 }; $failGroups[$k]++ }

    foreach ($f in $failures) {
        $k = if ($f.KB) { $f.KB } else { $f.Title }
        $f.FailCount = $failGroups[$k]
        $later = @($successes | Where-Object { $_.DateObj -and $f.DateObj -and $_.DateObj -gt $f.DateObj })

        # 1. Same update later succeeded
        $same = $later | Where-Object { ($f.KB -and $_.KB -eq $f.KB) -or (-not $f.KB -and $_.Title -eq $f.Title) } | Select-Object -First 1
        if ($same) { $f.Resolution = 'Resolved'; $f.ResolutionDetail = "Same update installed successfully on $($same.Date)"; continue }
        if ($f.KB -and $installedKbs.ContainsKey($f.KB.ToUpper())) { $f.Resolution = 'Resolved'; $f.ResolutionDetail = "$($f.KB) is listed as installed"; continue }

        switch ($f.Category) {
            'Cumulative update' {
                $lcu = $later | Where-Object { $_.Category -in @('Cumulative update','Feature update') } | Sort-Object DateObj | Select-Object -Last 1
                if ($lcu) { $f.Resolution = 'Superseded'; $f.ResolutionDetail = "Cumulative updates include earlier fixes. Newer one installed: $($lcu.Title) ($($lcu.Date)). Current build $($script:CurrentBuild).$($script:CurrentUBR)" }
            }
            'Feature update' {
                $feat = $later | Where-Object { $_.Category -eq 'Feature update' } | Select-Object -Last 1
                if ($feat) { $f.Resolution = 'Superseded'; $f.ResolutionDetail = "Later feature update succeeded: $($feat.Title)" }
                elseif ($script:CurrentDisplayVersion -and $f.Title -match [regex]::Escape($script:CurrentDisplayVersion)) {
                    $f.Resolution = 'Resolved'; $f.ResolutionDetail = "PC is now on version $($script:CurrentDisplayVersion)"
                } else {
                    $verInTitle = $null; if ($f.Title -match '(\d{2}H\d)') { $verInTitle = $Matches[1] }
                    if ($verInTitle -and $script:CurrentDisplayVersion -and ($script:CurrentDisplayVersion -gt $verInTitle)) {
                        $f.Resolution = 'Superseded'; $f.ResolutionDetail = "PC is now on newer version $($script:CurrentDisplayVersion)"
                    }
                }
            }
            { $_ -in @('Defender','MSRT','Servicing stack','WinRE / Safe OS','Microsoft app') } {
                $cat = $f.Category
                $next = $later | Where-Object { $_.Category -eq $cat } | Sort-Object DateObj | Select-Object -Last 1
                if ($next) { $f.Resolution = 'Superseded'; $f.ResolutionDetail = "Newer $cat update installed: $($next.Title) ($($next.Date))" }
            }
            '.NET' {
                $target = $null; if ($f.Title -match '(?i)for (\.NET.+?) for ') { $target = $Matches[1] }
                $next = $later | Where-Object { $_.Category -eq '.NET' -and (-not $target -or $_.Title -like "*$target*") } | Sort-Object DateObj | Select-Object -Last 1
                if (-not $next) { $next = $later | Where-Object { $_.Category -eq '.NET' } | Sort-Object DateObj | Select-Object -Last 1; if ($next) { $f.Resolution = 'Probably superseded' } }
                else { $f.Resolution = 'Superseded' }
                if ($next) { $f.ResolutionDetail = "Newer .NET cumulative update installed: $($next.Title) ($($next.Date))" }
            }
            'Driver / firmware' {
                $nextDrv = $later | Where-Object { $_.DriverVendor -eq $f.DriverVendor -and $_.DriverClass -eq $f.DriverClass } | Sort-Object DateObj | Select-Object -Last 1
                if ($nextDrv) { $f.Resolution = 'Superseded'; $f.ResolutionDetail = "Later driver from same vendor/class installed: $($nextDrv.Title)" }
                elseif ($f.DriverVersion) {
                    $fv = ConvertTo-VersionSafe $f.DriverVersion
                    $match = $script:DeviceList | Where-Object { $_.Version -and $_.Version -eq $f.DriverVersion } | Select-Object -First 1
                    if ($match) { $f.Resolution = 'Resolved'; $f.ResolutionDetail = "Driver version $($f.DriverVersion) is installed on: $($match.Name)" }
                    elseif ($fv) {
                        $vendorWord = ($f.DriverVendor -split '\s')[0]
                        $newer = $script:DeviceList | Where-Object {
                            $_.Provider -and $_.Provider -like "*$vendorWord*" -and $_.Version -and (ConvertTo-VersionSafe $_.Version) -and
                            ((ConvertTo-VersionSafe $_.Version).Major -eq $fv.Major) -and ((ConvertTo-VersionSafe $_.Version) -ge $fv) } | Select-Object -First 1
                        if ($newer) { $f.Resolution = 'Probably resolved'; $f.ResolutionDetail = "Same or newer $vendorWord driver installed: $($newer.Name) $($newer.Version)" }
                    }
                }
            }
        }
        if (-not $f.Resolution) { $f.Resolution = 'Unresolved'; $f.ResolutionDetail = 'No later successful install or newer replacement found in history. Check if Windows Update still offers it.' }
    }

    # Failure events from the System log (survive even when history list is short)
    $wuEvents = @()
    try {
        $wuEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WindowsUpdateClient'; Id = 20 } -MaxEvents 300 -ErrorAction Stop | ForEach-Object {
            $msg = $_.Message
            $code = $null; if ($msg -match '0x[0-9A-Fa-f]{8}') { $code = $Matches[0].ToUpper() -replace '^0X','0x' }
            [ordered]@{ Date = Format-Time $_.TimeCreated; Message = Get-Trimmed $msg 400; Code = $code
                        ErrorMeaning = if ($code -and $WuErrors.ContainsKey($code)) { $WuErrors[$code] } else { $null } }
        })
    } catch { if ($_.Exception.Message -notmatch 'No events were found') { Add-Note 'Windows Update events' $_.Exception.Message } }

    $script:Audit.WindowsUpdate = [ordered]@{
        HistoryCount = $entries.Count
        HistoryStarts = Format-Date $earliest
        Failures = @($failures | Select-Object @{ n = 'Key'; e = { 'wu|' + $(if ($_.KB) { $_.KB } else { $_.Title }) } }, Date, Title, KB, Category, Result, HResult, ErrorMeaning, FailCount, Resolution, ResolutionDetail)
        History = @($entries | Select-Object Date, Title, KB, Category, Operation, Result, HResult, ErrorMeaning, Resolution, ResolutionDetail)
        InstalledHotfixes = $hotfixes
        FailureEvents = $wuEvents
        Pending = $null
    }
}

# Optional: ask Windows Update what is currently offered (read-only search)
if ($CheckWindowsUpdate) {
    Invoke-Section 'Searching Windows Update for offered updates (read-only, may take a few minutes)' {
        $session = New-Object -ComObject Microsoft.Update.Session
        $session.ClientApplicationID = 'PC Audit (read-only scan)'
        $searcher = $session.CreateUpdateSearcher()
        $searcher.Online = $true
        $res = $searcher.Search("IsInstalled=0 and IsHidden=0")
        $pending = foreach ($u in $res.Updates) {
            $kb = $null; if ($u.KBArticleIDs.Count -gt 0) { $kb = "KB$($u.KBArticleIDs.Item(0))" }
            $isDriver = ([int]$u.Type -eq 2)
            [ordered]@{
                Title = $u.Title; KB = $kb; Type = $(if ($isDriver) { 'Driver' } else { 'Software' })
                Category = Get-UpdateCategory $u.Title
                SizeMB = [math]::Round($u.MaxDownloadSize / 1MB, 1); Downloaded = $u.IsDownloaded
                Severity = $u.MsrcSeverity; Released = Format-Date $u.LastDeploymentChangeTime
                AutoSelected = $u.AutoSelectOnWebSites
                DriverHardwareID = $(if ($isDriver) { $u.DriverHardwareID } else { $null })
                DriverClass = $(if ($isDriver) { $u.DriverClass } else { $null })
                DriverManufacturer = $(if ($isDriver) { $u.DriverManufacturer } else { $null })
                DriverModel = $(if ($isDriver) { $u.DriverModel } else { $null })
                DriverDate = $(if ($isDriver) { Format-Date $u.DriverVerDate } else { $null })
            }
        }
        $pending = @($pending)
        $script:Audit.WindowsUpdate.Pending = $pending
        # Mark unresolved failures that are still being offered
        foreach ($f in $script:Audit.WindowsUpdate.Failures) {
            if ($f.Resolution -eq 'Unresolved') {
                $p = $pending | Where-Object { ($f.KB -and $_.KB -eq $f.KB) -or $_.Title -eq $f.Title } | Select-Object -First 1
                if ($p) { $f.Resolution = 'Still pending'; $f.ResolutionDetail = 'Windows Update is still offering this update - it has not been installed yet.' }
                elseif ($f.Category -eq 'Driver / firmware' -and $f.Title -match '^\s*(.+?) - (.+?) - ') {
                    $v = $Matches[1]; $c = $Matches[2]
                    $p = $pending | Where-Object { $_.Type -eq 'Driver' -and $_.Title -like "$v - $c - *" } | Select-Object -First 1
                    if ($p) { $f.Resolution = 'Still pending'; $f.ResolutionDetail = "A newer driver from the same vendor is offered and not yet installed: $($p.Title)" }
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 6. Event log scan for driver / hardware problems
# ---------------------------------------------------------------------------
function Get-EventSignature($providerName, [int]$id) {
    foreach ($sig in $EventSignatures) {
        if ($providerName -match $sig.P -and ($sig.I.Count -eq 0 -or $sig.I -contains $id)) { return $sig }
    }
    return $null
}

Invoke-Section "Event logs (last $EventDays days)" {
    $since = (Get-Date).AddDays(-$EventDays)
    $deviceByService = @{}
    foreach ($d in $script:DeviceList) { if ($d.Service -and -not $deviceByService.ContainsKey($d.Service.ToUpper())) { $deviceByService[$d.Service.ToUpper()] = $d.Name } }
    $deviceByInstance = @{}
    foreach ($d in $script:DeviceList) { $deviceByInstance[$d.InstanceId.ToUpper()] = $d.Name }

    $events = @()
    try { $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1,2,3; StartTime = $since } -MaxEvents 20000 -ErrorAction Stop) }
    catch { if ($_.Exception.Message -notmatch 'No events') { Add-Note 'System event log' $_.Exception.Message } }
    try { $events += @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Kernel-PnP/Configuration'; Level = 1,2,3; StartTime = $since } -MaxEvents 2000 -ErrorAction Stop) } catch {}

    $groups = @{}
    foreach ($ev in $events) {
        $sig = Get-EventSignature $ev.ProviderName $ev.Id
        # Warnings only when they match a known signature; errors/critical always
        if ($ev.Level -eq 3 -and -not $sig) { continue }
        $key = "$($ev.ProviderName)|$($ev.Id)"
        if (-not $groups.ContainsKey($key)) {
            $msg = $null; try { $msg = $ev.Message } catch {}
            if (-not $msg) { $msg = ($ev.Properties | ForEach-Object { $_.Value }) -join ' | ' }
            $related = New-Object System.Collections.Generic.HashSet[string]
            $groups[$key] = [ordered]@{
                Provider = $ev.ProviderName; Id = $ev.Id; Log = $ev.LogName
                Level = if ($ev.LevelDisplayName) { $ev.LevelDisplayName } else { [string]$ev.Level }
                Count = 0; First = $ev.TimeCreated; Last = $ev.TimeCreated
                Category = if ($sig) { $sig.C } else { 'Other errors' }
                Severity = if ($sig) { $sig.S } else { 'low' }
                Hint = if ($sig) { $sig.H } else { $null }
                Sample = Get-Trimmed $msg 600
                RelatedDevices = $related
            }
        }
        $g = $groups[$key]
        $when = $ev.TimeCreated
        if ($ev.ProviderName -eq 'Microsoft-Windows-WER-SystemErrorReporting' -or ($ev.ProviderName -eq 'Windows Error Reporting' -and $ev.Id -eq 1001)) {
            $m1 = $null; try { $m1 = $ev.Message } catch {}
            $occ = Get-WerOccurrence ([string]$m1) $ev.TimeCreated
            if (-not $g.Contains('Seen')) { $g.Seen = @{}; $g.Logged = 0; $g.First = $occ.When; $g.Last = $occ.When }
            $g.Logged++
            if ($occ.Id) { if ($g.Seen.ContainsKey($occ.Id)) { continue }; $g.Seen[$occ.Id] = $true }
            $when = $occ.When
        }
        $g.Count++
        if ($when -lt $g.First) { $g.First = $when }
        if ($when -gt $g.Last) { $g.Last = $when }
        if ($g.RelatedDevices.Count -lt 5) {
            if ($deviceByService.ContainsKey($ev.ProviderName.ToUpper())) { [void]$g.RelatedDevices.Add($deviceByService[$ev.ProviderName.ToUpper()]) }
            if ($ev.ProviderName -match 'Kernel-PnP' -or $ev.Id -in @(219, 411, 7026)) {
                $m = $null; try { $m = $ev.Message } catch {}
                if ($m) {
                    foreach ($mm in [regex]::Matches($m, '(?i)\b(PCI|USB|ACPI|HDAUDIO|INTELAUDIO|SWD|ROOT|BTHENUM|BTHLE\w*|HID|SCSI|DISPLAY|UEFI|STORAGE)\\[^\s"]+')) {
                        $inst = $mm.Value.TrimEnd('.', ',').ToUpper()
                        if ($deviceByInstance.ContainsKey($inst)) { [void]$g.RelatedDevices.Add($deviceByInstance[$inst]) } else { [void]$g.RelatedDevices.Add($mm.Value.TrimEnd('.', ',')) }
                    }
                }
            }
        }
    }

    # Application crashes in GPU driver modules, and LiveKernelEvents (GPU / hardware hangs)
    $appGroups = @{}
    try {
        $appEvents = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Application Error','Windows Error Reporting'; StartTime = $since } -MaxEvents 5000 -ErrorAction Stop)
        foreach ($ev in $appEvents) {
            $m = $null; try { $m = $ev.Message } catch {}
            if (-not $m) { continue }
            $key = $null; $cat = $null; $hint = $null; $sev = 'medium'
            if ($ev.ProviderName -eq 'Application Error' -and $m -match $GpuModulesRegex) {
                $mod = $Matches[1]; $key = "GPU-module|$mod"; $cat = 'Graphics'
                $hint = "Applications crashed inside graphics driver module $mod.dll. Update or clean-install the GPU driver."
            } elseif ($m -match 'LiveKernelEvent') {
                $code = $null; if ($m -match 'P1:\s*([0-9a-fA-F]+)') { $code = $Matches[1] }
                $key = "LKE|$code"; $cat = 'Graphics / hardware hang'; $sev = 'high'
                $known = @{ '141' = 'GPU stopped responding (VIDEO_ENGINE_TIMEOUT_DETECTED)'; '117' = 'GPU timeout (VIDEO_TDR_TIMEOUT_DETECTED)';
                            '1a8' = 'Connected standby watchdog'; '193' = 'Video DXGKRNL livedump'; '144' = 'USB4/Thunderbolt livedump'; 'ab' = 'Session has open handles'; '15e' = 'Bugcheck in hardware'; '1b8' = 'GPU (DxgKrnl) livedump' }
                $hint = 'Live kernel event (non-fatal hang dump). '
                if ($code -and $known.ContainsKey($code.ToLower())) { $hint += $known[$code.ToLower()] + '.' }
                $hint += ' Most often a GPU driver/hardware hang - update GPU driver, check temps/power.'
            }
            if ($key) {
                if (-not $appGroups.ContainsKey($key)) {
                    $label = if ($key -like 'GPU-module|*') { "App crash in $($key.Split('|')[1]).dll" } else { "LiveKernelEvent $($key.Split('|')[1])" }
                    $appGroups[$key] = [ordered]@{ Provider = $label; Id = $ev.Id; Log = 'Application'; Level = 'Error'; Count = 0
                        First = $ev.TimeCreated; Last = $ev.TimeCreated; Category = $cat; Severity = $sev; Hint = $hint; Sample = Get-Trimmed $m 600
                        RelatedDevices = (New-Object System.Collections.Generic.HashSet[string]) }
                }
                $g = $appGroups[$key]
                $occ = if ($key -like 'LKE|*') { Get-WerOccurrence $m $ev.TimeCreated } else { [pscustomobject]@{ Id = $null; When = $ev.TimeCreated } }
                if (-not $g.Contains('Seen')) { $g.Seen = @{}; $g.Logged = 0; $g.First = $occ.When; $g.Last = $occ.When }
                $g.Logged++
                if ($occ.Id) { if ($g.Seen.ContainsKey($occ.Id)) { continue }; $g.Seen[$occ.Id] = $true }
                $g.Count++
                if ($occ.When -lt $g.First) { $g.First = $occ.When }
                if ($occ.When -gt $g.Last) { $g.Last = $occ.When }
            }
        }
    } catch { if ($_.Exception.Message -notmatch 'No events') { Add-Note 'Application event log' $_.Exception.Message } }

    $sevRank = @{ high = 0; medium = 1; low = 2; info = 3 }
    $all = @($groups.Values) + @($appGroups.Values)
    $script:Audit.EventIssues = @($all | ForEach-Object {
        [pscustomobject][ordered]@{ Key = "event|$($_.Provider)|$($_.Id)"; Severity = $_.Severity; Category = $_.Category; Provider = $_.Provider; Id = $_.Id; Log = $_.Log; Level = $_.Level
            Count = $_.Count; Logged = $(if ($_.Contains('Logged') -and $_.Logged -gt $_.Count) { $_.Logged } else { $null }); First = Format-Time $_.First; Last = Format-Time $_.Last; Hint = $_.Hint
            RelatedDevices = @($_.RelatedDevices); Sample = $_.Sample }
    } | Sort-Object @{e={ $sevRank[$_.Severity] }}, @{e={ $_.Count }; Descending = $true })
}

# ---------------------------------------------------------------------------
# 7. Crashes (BSOD) and dumps
# ---------------------------------------------------------------------------
Invoke-Section 'Crashes and dump files' {
    $bsods = @()
    try {
        $bsods = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001 } -MaxEvents 100 -ErrorAction Stop | ForEach-Object {
            $m = $_.Message; $code = $null; $name = $null; $params = $null
            if ($m -match '0x([0-9a-fA-F]{8,16})\s*\(([^)]*)\)') {
                $code = '0x' + $Matches[1].ToUpper(); $params = $Matches[2]
                try { $n = [Convert]::ToInt64($Matches[1], 16); if ($BugChecks.ContainsKey([int]$n)) { $name = $BugChecks[[int]$n] } } catch {}
            }
            $dump = $null; if ($m -match '([A-Z]:\\[^\s]+\.dmp)') { $dump = $Matches[1] }
            [ordered]@{ Date = Format-Time $_.TimeCreated; Code = $code; Name = $name; Parameters = $params; Dump = $dump }
        })
    } catch { if ($_.Exception.Message -notmatch 'No events') { Add-Note 'BSOD events' $_.Exception.Message } }
    # The same crash can be reported more than once (queued reports are re-sent): keep one row per dump file
    $bsods = @($bsods | Sort-Object { $_.Date } | Group-Object { if ($_.Dump) { $_.Dump.ToUpper() } else { $_.Date } } | ForEach-Object { $_.Group[0] } | Sort-Object { $_.Date } -Descending)

    $dumps = New-Object System.Collections.Generic.List[object]
    foreach ($pattern in @("$env:windir\Minidump\*.dmp", "$env:windir\MEMORY.DMP", "$env:windir\LiveKernelReports\*\*.dmp", "$env:windir\LiveKernelReports\*.dmp")) {
        try {
            Get-ChildItem -Path $pattern -ErrorAction Stop | ForEach-Object {
                $dumps.Add([pscustomobject]@{ Path = $_.FullName; Date = Format-Time $_.LastWriteTime; SizeMB = [math]::Round($_.Length / 1MB, 1)
                                              Type = $(if ($_.FullName -match 'LiveKernelReports') { 'Live kernel (hang)' } elseif ($_.Name -eq 'MEMORY.DMP') { 'Full/kernel dump' } else { 'Minidump (BSOD)' }) })
            }
        } catch {}
    }
    if (-not $IsAdmin -and $dumps.Count -eq 0) { Add-Note 'Dump files' 'Dump folders usually need admin to list.' }

    $unexpected = 0
    try { $unexpected = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = (Get-Date).AddDays(-$EventDays) } -ErrorAction Stop).Count } catch {}

    $script:Audit.Crashes = [ordered]@{ BugChecks = $bsods; Dumps = @($dumps | Sort-Object Date -Descending); UnexpectedRestartsInWindow = $unexpected }
}

# ---------------------------------------------------------------------------
# 8. Driver install failures (setupapi.dev.log)
# ---------------------------------------------------------------------------
Invoke-Section 'Driver install log (setupapi.dev.log)' {
    $failures = New-Object System.Collections.Generic.List[object]
    $installs = New-Object System.Collections.Generic.List[object]
    $files = @(Get-ChildItem "$env:windir\INF\setupapi.dev*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime)
    foreach ($file in $files) {
        $lines = Read-SharedTail $file.FullName 16MB
        $header = $null; $start = $null; $errs = New-Object System.Collections.Generic.List[string]; $sel = @{}; $nodes = @(); $node = $null; $inSel = $false
        foreach ($line in $lines) {
            if ($line -match '^>>>\s+\[(.+)\]\s*$') { $header = $Matches[1]; $start = $null; $errs.Clear(); $sel = @{}; $nodes = @(); $node = $null; $inSel = $false; continue }
            if ($header) {
                # Driver details appear as "Created Driver Node:" blocks (one per candidate) and a "Selected Driver:" block.
                # Values may or may not be in [brackets] depending on the Windows build.
                if ($line -match '^\s*\w+:\s+Created Driver Node:') { $node = @{}; $nodes += $node; $inSel = $false; continue }
                if ($line -match '^\s*\w+:\s+Selected Driver:') { $inSel = $true; $node = $null; continue }
                if ($line -match '^\s*\w+:\s+(Description|DevDesc|InfFile|InfName|ProviderName|Provider|DrvDate|Version)\s*-\s*\[?(.*?)\]?\s*$') {
                    $k = $Matches[1]; $v = $Matches[2].Trim()
                    if ($inSel) { $sel[$k] = $v } elseif ($node) { $node[$k] = $v } else { $sel[$k] = $v }
                    continue
                }
            }
            if ($line -match '^>>>\s+Section start (\S+ \S+)') { $start = $Matches[1]; continue }
            if ($line -match '^\s*!!!\s+(.+)$' -and $errs.Count -lt 6) { $errs.Add($Matches[1].Trim()); continue }
            if ($line -match '^<<<\s+\[Exit status:\s*(.+?)\]') {
                $status = $Matches[1]
                if ($status -notmatch '^SUCCESS' -and $header) {
                    $inst = $null; if ($header -match ' - (.+)$') { $inst = $Matches[1] }
                    $devName = $null
                    if ($inst) { $d = $script:DeviceList | Where-Object { $_.InstanceId -eq $inst.ToUpper() } | Select-Object -First 1; if ($d) { $devName = $d.Name } }
                    $failures.Add([pscustomobject][ordered]@{ Date = $(try { ([datetime]::ParseExact(($start -replace '\.\d+$', ''), 'yyyy/MM/dd HH:mm:ss', $null)).ToString('yyyy-MM-ddTHH:mm:ss') } catch { $start }); Operation = $header; Device = $devName; Status = $status; Errors = $errs.ToArray() })
                }
                elseif ($header -and $header -match '^Device Install \(([^)]+)\) - (.+)$' -and $(
                        # Fill in the selected driver's version from its driver node
                        if (-not $sel.Version -and $nodes.Count) {
                            $pick = $null
                            if ($sel.InfFile) { $pick = $nodes | Where-Object { $_.InfName -and ((Split-Path $_.InfName -Leaf) -eq (Split-Path $sel.InfFile -Leaf)) } | Select-Object -Last 1 }
                            if (-not $pick -and $nodes.Count -eq 1) { $pick = $nodes[0] }
                            if ($pick) { foreach ($k in @('Version', 'DrvDate', 'ProviderName', 'Provider')) { if ($pick[$k] -and -not $sel[$k]) { $sel[$k] = $pick[$k] } }; if (-not $sel.Description) { $sel.Description = $pick.DevDesc }; if (-not $sel.InfFile) { $sel.InfFile = $pick.InfName } }
                        }
                        [bool]$sel.Version)) {
                    # A successful driver install: what, when, and how it was started
                    $how = $Matches[1]; $inst = $Matches[2].Trim().ToUpper()
                    $dev = $script:DeviceList | Where-Object { $_.InstanceId -eq $inst } | Select-Object -First 1
                    if (-not $dev -or $dev.IsHardware) {
                        $method = switch -Regex ($how) {
                            'Hardware initiated' { 'Windows (device detected)' }
                            'DiShowUpdateDevice|DiShowUpdateDriver' { 'Device Manager' }
                            'UpdateDriverForPlugAndPlayDevices|DiInstallDriver' { 'Installer or pnputil' }
                            'DiInstallDevice' { 'Windows Update or installer' }
                            default { $how }
                        }
                        $installs.Add([pscustomobject][ordered]@{
                            Date = $(try { ([datetime]::ParseExact(($start -replace '\.\d+$', ''), 'yyyy/MM/dd HH:mm:ss', $null)).ToString('yyyy-MM-ddTHH:mm:ss') } catch { $start })
                            Device = $(if ($dev) { $dev.Name } elseif ($sel.Description) { $sel.Description } else { $inst })
                            InstanceId = $inst; Version = $sel.Version; DriverDate = $sel.DrvDate; Provider = $(if ($sel.ProviderName) { $sel.ProviderName } else { $sel.Provider })
                            Inf = $(if ($sel.InfFile) { Split-Path $sel.InfFile -Leaf }); Method = $method })
                    }
                }
                $header = $null; $errs = New-Object System.Collections.Generic.List[string]; $nodes = @(); $node = $null; $inSel = $false
            }
        }
    }
    $script:Audit.DriverInstallFailures = @($failures | Sort-Object Date -Descending | Select-Object -First 200)
    $script:DriverInstalls = @($installs | Sort-Object Date -Descending | Select-Object -First 400)
}

# ---------------------------------------------------------------------------
# 9. Servicing (CBS) and upgrade (Panther) logs
# ---------------------------------------------------------------------------
Invoke-Section 'Servicing (CBS) and upgrade (Panther) logs' {
    $cbs = [ordered]@{ Readable = $false; TopErrors = @(); RecentErrors = @() }
    $cbsPath = "$env:windir\Logs\CBS\CBS.log"
    if (Test-Path $cbsPath) {
        try {
            $lines = Read-SharedTail $cbsPath 12MB
            $cbs.Readable = $true
            $errLines = @($lines | Where-Object { ($_ -match ',\s+Error\s+') -or (($_ -match '\b(HRESULT|hr)\s*=\s*0x8') -and ($_ -match '(?i)fail')) })
            $codes = @{}
            foreach ($l in $errLines) {
                foreach ($m in [regex]::Matches($l, '0x[0-9A-Fa-f]{8}')) {
                    $c = '0x' + $m.Value.Substring(2).ToUpper()
                    if ($c -eq '0x00000000') { continue }
                    if (-not $codes.ContainsKey($c)) { $codes[$c] = [ordered]@{ Code = $c; Count = 0; Last = $null; Meaning = $(if ($WuErrors.ContainsKey($c)) { $WuErrors[$c] } else { $null }) } }
                    $codes[$c].Count++; $codes[$c].Last = ($l.Substring(0, [Math]::Min(19, $l.Length)))
                }
            }
            $cbs.TopErrors = @($codes.Values | Sort-Object { $_.Count } -Descending | Select-Object -First 15)
            $cbs.RecentErrors = @($errLines | Select-Object -Last 25 | ForEach-Object { Get-Trimmed $_ 300 })
        } catch { $cbs.Note = "Cannot read CBS.log: $($_.Exception.Message)" }
    }
    # CheckSUR / component store corruption markers from last sfc/dism run
    $cbsPersist = $null
    if ($cbs.Readable) {
        $sfc = @($lines | Where-Object { $_ -match 'Windows Resource Protection found|Verify complete|Repair complete|corrupt' } | Select-Object -Last 5)
        if ($sfc.Count) { $cbsPersist = @($sfc | ForEach-Object { Get-Trimmed $_ 250 }) }
    }
    $cbs.SfcDismMarkers = $cbsPersist

    $panther = New-Object System.Collections.Generic.List[object]
    $candidates = @(
        @{ Path = "$env:windir\Panther\setuperr.log";               Label = 'Last completed setup/upgrade' }
        @{ Path = 'C:\$WINDOWS.~BT\Sources\Panther\setuperr.log';  Label = 'Upgrade attempt in progress or failed (staging folder)' }
        @{ Path = 'C:\$WINDOWS.~BT\Sources\Rollback\setuperr.log'; Label = 'ROLLBACK - a feature upgrade failed and was rolled back' }
        @{ Path = "$env:windir\Panther\NewOs\Panther\setuperr.log"; Label = 'Upgrade (new OS phase)' }
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c.Path) {
            try {
                $item = Get-Item -LiteralPath $c.Path -Force
                $l = @(Read-SharedTail $c.Path 2MB | Where-Object { $_.Trim() })
                $panther.Add([pscustomobject][ordered]@{ Path = $c.Path; Meaning = $c.Label; LastWrite = Format-Time $item.LastWriteTime
                                                         ErrorLines = $l.Count; LastLines = @($l | Select-Object -Last 15 | ForEach-Object { Get-Trimmed $_ 300 }) })
            } catch { $panther.Add([pscustomobject]@{ Path = $c.Path; Meaning = $c.Label; Note = $_.Exception.Message }) }
        }
    }
    $rollback = Test-Path -LiteralPath 'C:\$WINDOWS.~BT\Sources\Rollback'
    $winOld = Test-Path -LiteralPath 'C:\Windows.old'
    $script:Audit.ServicingLogs = [ordered]@{ CBS = $cbs; Panther = $panther.ToArray(); RollbackFolderPresent = $rollback; WindowsOldPresent = $winOld
        SetupDiagUrl = 'https://learn.microsoft.com/windows/deployment/upgrade/setupdiag' }
}

# ---------------------------------------------------------------------------
# 10. Reliability history (longer than event logs, ~1 year)
# ---------------------------------------------------------------------------
Invoke-Section 'Reliability history (last 12 months)' {
    $since = (Get-Date).AddDays(-365).ToUniversalTime().ToString('yyyyMMddHHmmss') + '.000000+000'
    $recs = @(Get-CimInstance Win32_ReliabilityRecords -Filter "TimeGenerated > '$since'" -ErrorAction Stop)
    $byMonth = @{}
    foreach ($r in $recs) {
        $cat = switch -Regex ($r.SourceName) {
            'WindowsUpdateClient' { if ($r.EventIdentifier -eq 20) { 'Update failed' } elseif ($r.EventIdentifier -eq 19) { 'Update installed' } else { $null } }
            'WER-SystemErrorReporting|BugCheck' { 'Blue screen' }
            '^EventLog$' { 'Unexpected shutdown' }
            'Application Error' { 'App crash' }
            'Application Hang' { 'App hang' }
            'Windows Error Reporting' { if ($r.Message -match 'LiveKernelEvent') { 'Hardware/GPU hang' } else { $null } }
            'MsiInstaller' { $null }
            default { $null }
        }
        if (-not $cat) { continue }
        $mo = ([datetime]$r.TimeGenerated).ToString('yyyy-MM')
        if (-not $byMonth.ContainsKey($mo)) { $byMonth[$mo] = @{} }
        if (-not $byMonth[$mo].ContainsKey($cat)) { $byMonth[$mo][$cat] = 0 }
        $byMonth[$mo][$cat]++
    }
    $script:Audit.Reliability = @($byMonth.Keys | Sort-Object | ForEach-Object {
        $m = $_; $o = [ordered]@{ Month = $m }
        foreach ($c in @('Blue screen','Unexpected shutdown','Hardware/GPU hang','Update failed','Update installed','App crash','App hang')) { $o[$c] = [int]$byMonth[$m][$c] }
        [pscustomobject]$o
    })
}

# ---------------------------------------------------------------------------
# 11. Online lookups: board maker BIOS + drivers, GPU driver, part links
#     Read-only web requests to the manufacturers' own support sites/APIs.
# ---------------------------------------------------------------------------
$script:HttpNotes = New-Object System.Collections.Generic.List[object]

$script:BrowserUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0'
function Test-BotChallenge([string]$c) { return ($c -match '_Incapsula_Resource|cf-chl-|<title>Just a moment|challenge-platform') }

function Invoke-Http([string]$Url, [switch]$Json, [string]$Source = '', $Session = $null, [switch]$Quiet) {
    $h = @{ 'Accept-Language' = 'en-US,en;q=0.9'; 'Accept' = 'text/html,application/xhtml+xml,application/xml;q=0.9,application/json;q=0.8,*/*;q=0.7' }
    try {
        $p = @{ Uri = $Url; Headers = $h; UserAgent = $script:BrowserUA; UseBasicParsing = $true; TimeoutSec = 40; ErrorAction = 'Stop' }
        if ($Session) { $p.WebSession = $Session }
        $r = Invoke-WebRequest @p
        $c = $r.Content
        if ($c -is [byte[]]) { $c = [Text.Encoding]::UTF8.GetString($c) }
        if (Test-BotChallenge $c) {
            if (-not $Quiet) { $script:HttpNotes.Add([pscustomobject]@{ Source = $Source; Url = $Url; Message = 'Blocked by the site''s bot protection - use the direct link instead' }) }
            return $null
        }
        if ($Json) {
            $t = $c.Trim()
            if ($t -match '(?s)^[\w\.\$]+\((.*)\)\s*;?\s*$') { $t = $Matches[1] }
            return ($t | ConvertFrom-Json)
        }
        return $c
    } catch {
        $code = $null; try { $code = [int]$_.Exception.Response.StatusCode } catch {}
        $msg = if ($code) { "HTTP $code" } else { $_.Exception.Message }
        $script:HttpNotes.Add([pscustomobject]@{ Source = $Source; Url = $Url; Message = $msg })
        return $null
    }
}

function ConvertFrom-HtmlText([string]$h) {
    if (-not $h) { return '' }
    $t = $h -replace '(?is)<(script|style)\b.*?</\1>', ' ' -replace '(?i)<br\s*/?>', ' ' -replace '<[^>]+>', ' '
    $t = [System.Net.WebUtility]::HtmlDecode($t)
    return ($t -replace '\s+', ' ').Trim()
}

function Get-HtmlTableRows([string]$html) {
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($tr in [regex]::Matches($html, '(?is)<tr\b.*?</tr>')) {
        $cells = @([regex]::Matches($tr.Value, '(?is)<t[dh]\b[^>]*>(.*?)</t[dh]>') | ForEach-Object { $_.Groups[1].Value })
        if ($cells.Count -eq 0) { continue }
        $rows.Add([pscustomobject]@{
            Text  = @($cells | ForEach-Object { ConvertFrom-HtmlText $_ })
            Links = @([regex]::Matches($tr.Value, '(?i)href\s*=\s*["'']([^"'']+)["'']') | ForEach-Object { [System.Net.WebUtility]::HtmlDecode($_.Groups[1].Value) })
        })
    }
    return , $rows.ToArray()
}

function Get-NumericVersion([string]$s) {
    if (-not $s) { return $null }
    $m = [regex]::Match($s, '\d+(\.\d+)+'); if ($m.Success) { return $m.Value }
    $m = [regex]::Match($s, '\d+'); if ($m.Success) { return $m.Value }
    return $null
}

function Compare-NumericVersion([string]$a, [string]$b) {
    $na = Get-NumericVersion $a; $nb = Get-NumericVersion $b
    if (-not $na -or -not $nb) { return $null }
    $pa = @($na.Split('.')); $pb = @($nb.Split('.'))
    $n = [Math]::Max($pa.Count, $pb.Count)
    for ($i = 0; $i -lt $n; $i++) {
        $x = if ($i -lt $pa.Count) { [decimal]$pa[$i] } else { 0 }
        $y = if ($i -lt $pb.Count) { [decimal]$pb[$i] } else { 0 }
        if ($x -gt $y) { return 1 } elseif ($x -lt $y) { return -1 }
    }
    return 0
}

function ConvertTo-IsoDate([string]$s) {
    if (-not $s) { return $null }
    $m = [regex]::Match($s, '(\d{4})[/\-\.](\d{1,2})[/\-\.](\d{1,2})')
    if ($m.Success) { return ('{0}-{1:D2}-{2:D2}' -f $m.Groups[1].Value, [int]$m.Groups[2].Value, [int]$m.Groups[3].Value) }
    $d = [datetime]::MinValue
    $clean = $s -replace '^[A-Za-z]{3},?\s+', ''
    if ([datetime]::TryParse($clean, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$d)) { return $d.ToString('yyyy-MM-dd') }
    return $null
}

function Get-DriverCategory([string]$t) {
    switch -Regex ($t) {
        '(?i)google chrome|norton|mcafee|app shop|utility|armou?ry|center|rgb|polychrome|\bedge\b|steam|cfosspeed|live ?update|winrar|7-zip|restart to uefi|xfast|gamefirst|creator|sonic studio|nahimic|smart byte|dragon|msi center|easy tune|app center|@bios|ai suite' { return 'Utility' }
        '(?i)bluetooth'                          { return 'Bluetooth' }
        '(?i)wlan|wi-?fi|wireless'               { return 'WLAN' }
        '(?i)\blan\b|ethernet|network|i22[56]|2\.5g|killer' { return 'LAN' }
        '(?i)audio|sound'                        { return 'Audio' }
        '(?i)\bvga\b|graphics|\bapu\b|display'   { return 'Graphics' }
        '(?i)raid|sata|nvme|ahci|storage|\brst\b|\bvmd\b' { return 'Storage' }
        '(?i)chipset|\binf\b|smbus|management engine|serial ?io|gpio|\bnpu\b|usb' { return 'Chipset / platform' }
    }
    return 'Other'
}

$script:VendorWords = '(?i)\b(AMD|Intel|Realtek|NVIDIA|Killer|Qualcomm|MediaTek|Broadcom|Marvell|Aquantia|ASMedia)\b'
function Find-InstalledFor([string]$cat, [string]$text) {
    if ($cat -eq 'Chipset / platform') {
        $want = if ($text -match '(?i)AMD') { '(?i)AMD Chipset' } elseif ($text -match '(?i)Intel') { '(?i)Intel.*(Chipset|Serial IO|Management Engine)' } else { '(?i)chipset' }
        $p = @($script:DriverPrograms | Where-Object { $_.Name -match $want }) | Select-Object -First 1
        if ($p) { return [pscustomobject]@{ Name = $p.Name; Version = $p.Version; Date = $p.InstallDate; Kind = 'Installed program'; Provider = $p.Publisher } }
        return $null
    }
    $devs = @($script:DeviceList | Where-Object { $_.Present -and $_.IsHardware -and $_.Version })
    $cand = switch ($cat) {
        'LAN'       { $devs | Where-Object { $_.Class -eq 'Net' -and $_.Bus -eq 'PCI' -and $_.Name -notmatch '(?i)wi-?fi|wireless|wlan|802\.11' } }
        'WLAN'      { $devs | Where-Object { $_.Class -eq 'Net' -and $_.Name -match '(?i)wi-?fi|wireless|wlan|802\.11' } }
        'Bluetooth' { $devs | Where-Object { $_.Class -eq 'Bluetooth' -and $_.Bus -eq 'USB' } }
        'Audio'     { $devs | Where-Object { $_.Class -eq 'MEDIA' -and $_.Bus -match 'HDAUDIO|INTELAUDIO' -and $_.Name -notmatch '(?i)NVIDIA|AMD High Definition|Display Audio|HDMI|DisplayPort' } }
        'Graphics'  { $devs | Where-Object { $_.Class -eq 'Display' } }
        'Storage'   { $devs | Where-Object { $_.Class -in @('SCSIAdapter', 'HDC') -and $_.Provider -notmatch '^Microsoft' } }
        default     { @() }
    }
    $cand = @($cand)
    if ($cand.Count -eq 0) { return $null }
    $vm = [regex]::Match($text, $script:VendorWords)
    $pick = $null
    if ($vm.Success) {
        $v = $vm.Groups[1].Value
        $pick = $cand | Where-Object { "$($_.ChipVendor) $($_.Provider) $($_.Name)" -match "(?i)\b$v" } | Select-Object -First 1
        if (-not $pick) { return $null }   # e.g. board offers an AMD GPU driver but this PC has an NVIDIA card
    } else { $pick = $cand[0] }
    return [pscustomobject]@{ Name = $pick.Name; Version = $pick.Version; Date = $pick.Date; Kind = 'Device driver'; Provider = $pick.Provider }
}

function Get-OfferStatus([string]$offerVer, [string]$offerDate, $inst) {
    if (-not $inst) { return 'Not detected' }
    if ($inst.Kind -eq 'Device driver' -and $inst.Provider -match '^Microsoft') { return 'Generic Windows driver - vendor driver available' }
    $no = Get-NumericVersion $offerVer; $ni = Get-NumericVersion $inst.Version
    if ($no -and $ni) {
        if ($ni -eq $no -or $ni.EndsWith('.' + $no) -or $no.EndsWith('.' + $ni)) { return 'Up to date' }
        $po = $no.Split('.'); $pi = $ni.Split('.')
        if ($po.Count -eq $pi.Count -and ($po[0] -eq $pi[0] -or $inst.Kind -eq 'Installed program')) {
            $c = Compare-NumericVersion $no $ni
            if ($c -gt 0) { return 'Newer available' } elseif ($c -lt 0) { return 'Installed is newer' } else { return 'Up to date' }
        }
    }
    if ($offerDate -and $inst.Date) {
        try {
            $d = ([datetime]$offerDate - [datetime]$inst.Date).TotalDays
            if ($d -gt 60) { return 'Probably newer (by date)' } elseif ($d -lt -60) { return 'Installed is newer (by date)' }
        } catch {}
    }
    return 'Compare manually'
}

# Keep only the newest entry per driver (vendors list old versions too)
function Select-NewestOffers($offers) {
    $byKey = @{}
    foreach ($o in $offers) {
        $k = $o.Category + '|' + (($o.Name -replace '\d+(\.\d+)+', '' -replace '(?i)\bv(er)?\b', '' -replace '[^A-Za-z ]', ' ' -replace '\s+', ' ').Trim().ToLower())
        if (-not $byKey.ContainsKey($k) -or ($o.Date -and $byKey[$k].Date -and $o.Date -gt $byKey[$k].Date)) { $byKey[$k] = $o }
    }
    return @($byKey.Values | Sort-Object Category, Name)
}

function New-BiosResult($vendor, $model) {
    [ordered]@{ Vendor = $vendor; Model = $model; MatchedProduct = $null; PageUrl = $null; BiosPageUrl = $null
                Installed = $script:Audit.System.BIOS.Version; Latest = $null; LatestBeta = $null; NewerCount = $null; Status = 'Not checked'; Note = $null
                Revisions = @(); Versions = @() }
}

function Set-BiosStatus($res, [string]$installed, $entries, [scriptblock]$Normalize, [bool]$NumericFallback = $true) {
    # $entries: newest first, each with Version, Date, IsBeta, Url, Notes
    $res.Installed = $installed
    $res.Versions = @($entries | Select-Object -First 12)
    $stable = @($entries | Where-Object { -not $_.IsBeta })
    $res.Latest = if ($stable.Count) { $stable[0] } else { $entries | Select-Object -First 1 }
    $beta = $entries | Select-Object -First 1
    if ($beta -and $beta.IsBeta -and $res.Latest -and $beta.Date -ge $res.Latest.Date) { $res.LatestBeta = $beta }
    $ni = & $Normalize $installed
    $idx = -1
    for ($i = 0; $i -lt $stable.Count; $i++) { if ((& $Normalize $stable[$i].Version) -eq $ni) { $idx = $i; break } }
    if ($idx -ge 0) {
        $res.NewerCount = $idx
        $res.Status = if ($idx -eq 0) { 'Up to date' } else { "$idx newer version$(if ($idx -gt 1) { 's' }) available" }
    } elseif (-not $NumericFallback) {
        $res.Status = 'Compare manually'
        $res.Note = "Installed version '$installed' was not found in the maker's list - compare by hand."
    } else {
        $c = Compare-NumericVersion $ni (& $Normalize $res.Latest.Version)
        if ($c -eq -1) {
            $res.NewerCount = @($stable | Where-Object { (Compare-NumericVersion (& $Normalize $_.Version) $ni) -eq 1 }).Count
            $res.Status = "Newer version available"
        } elseif ($c -ge 0) { $res.Status = 'Up to date'; $res.NewerCount = 0 }
        else { $res.Status = 'Compare manually' }
    }
}

# --- Headless Microsoft Edge: last resort for sites whose bot protection needs JavaScript ---
function Stop-ProcessTree([int]$Id) {
    foreach ($c in @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$Id" -ErrorAction SilentlyContinue)) { Stop-ProcessTree ([int]$c.ProcessId) }
    Stop-Process -Id $Id -Force -ErrorAction SilentlyContinue
}

function Get-HtmlViaEdge([string]$Url, [int]$TimeoutSec = 45) {
    $edge = @("${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe", "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe") |
            Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
    if (-not $edge) { return $null }
    $tmp = Join-Path $env:TEMP ("pcaudit_edge_" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    try {
        # Edge prints the page's final HTML (after the site's JavaScript check has run) to standard output
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $edge
        $psi.Arguments = ('--headless=new --disable-gpu --no-first-run --no-default-browser-check --disable-extensions --mute-audio --user-data-dir="{0}" --virtual-time-budget=15000 --dump-dom "{1}"' -f (Join-Path $tmp 'profile'), $Url)
        $psi.UseShellExecute = $false; $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true
        $p = [System.Diagnostics.Process]::Start($psi)
        $outTask = $p.StandardOutput.ReadToEndAsync(); $errTask = $p.StandardError.ReadToEndAsync()
        if (-not $p.WaitForExit($TimeoutSec * 1000)) { Stop-ProcessTree $p.Id }
        $c = $null
        if ($outTask.Wait(5000)) { $c = $outTask.Result }
        if ($c -and -not (Test-BotChallenge $c)) { return $c }
        return $null
    } catch { return $null }
    finally { Start-Sleep -Milliseconds 300; Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

# ASRock pages sit behind Imperva/Incapsula bot protection. Try, in order:
#   1. plain request   2. a cookie session that first loads the product page like a browser, with a retry
#   3. headless Microsoft Edge (runs the protection's JavaScript check)
function Get-AsrockHtml([string]$Url, [string]$PageUrl, [string]$Source) {
    $c = Invoke-Http $Url -Source $Source -Quiet
    if ($c) { return $c }
    $sess = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    [void](Invoke-Http $PageUrl -Source $Source -Session $sess -Quiet)
    foreach ($wait in @(1500, 4000)) {
        Start-Sleep -Milliseconds $wait
        $c = Invoke-Http $Url -Source $Source -Session $sess -Quiet
        if ($c) { return $c }
    }
    Write-Host "    ASRock is blocking scripted requests; trying headless Microsoft Edge..." -ForegroundColor DarkGray
    $c = Get-HtmlViaEdge $Url
    if ($c) { $script:HttpNotes.Add([pscustomobject]@{ Source = $Source; Url = $Url; Message = 'Read through headless Microsoft Edge (site bot protection blocked the normal request)' }); return $c }
    $script:HttpNotes.Add([pscustomobject]@{ Source = $Source; Url = $Url; Message = 'Blocked by the site''s bot protection (plain request, cookie session and headless Edge all failed) - use the direct link instead' })
    return $null
}

# --- ASRock -----------------------------------------------------------------
function Get-AsrockBoard($model, $platform, $osTag) {
    $res = New-BiosResult 'ASRock' $model
    $enc = $model -replace ' ', '%20'
    $drivers = @()
    foreach ($site in @('https://www.asrock.com', 'https://pg.asrock.com')) {
        $html = Get-AsrockHtml "$site/MB/$platform/$enc/BIOS.html" "$site/MB/$platform/$enc/index.asp" 'ASRock BIOS'
        if (-not ($html -and $html -match '(?i)<table')) { continue }
        $res.PageUrl = "$site/MB/$platform/$enc/index.asp"; $res.BiosPageUrl = "$site/MB/$platform/$enc/index.asp#BIOS"
        $res.MatchedProduct = $model
        $entries = foreach ($r in (Get-HtmlTableRows $html)) {
            if ($r.Text.Count -lt 5 -or $r.Text[0] -match '(?i)^version') { continue }
            $url = $r.Links | Where-Object { $_ -match 'download\.asrock\.com' } | Select-Object -First 1
            [pscustomobject]@{ Version = ($r.Text[0] -replace '\s*\[?Beta\]?', '').Trim(); IsBeta = ($r.Text[0] -match '(?i)beta')
                               Date = ConvertTo-IsoDate $r.Text[1]; Size = $r.Text[2]
                               Notes = (($r.Text[4] -replace '(?i)SHA256:\s*[0-9a-f]+', '').Trim())
                               Url = if ($url) { $url -replace ' ', '%20' } else { $null } }
        }
        $entries = @($entries | Sort-Object Date -Descending)
        if ($entries.Count) { Set-BiosStatus $res $script:Audit.System.BIOS.Version $entries { param($v) Get-NumericVersion $v } }

        $dl = Get-AsrockHtml "$site/MB/$platform/$enc/Download.html" "$site/MB/$platform/$enc/index.asp" 'ASRock drivers'
        if ($dl) {
            $drivers = foreach ($r in (Get-HtmlTableRows $dl)) {
                if ($r.Text.Count -lt 4 -or $r.Text[0] -match '(?i)^description') { continue }
                if ($r.Text[1] -notmatch "Windows\W*$osTag") { continue }
                $desc = $r.Text[0] -replace '(?i)SHA256:\s*[0-9a-f]+', ''
                $name = ($desc -replace '(?i)\s*ver[:.]\s*\S+.*$', '').Trim()
                $ver = if ($desc -match '(?i)ver[:.]\s*(\S+)') { $Matches[1] } else { $null }
                $url = $r.Links | Where-Object { $_ -match 'download\.asrock\.com' } | Select-Object -First 1
                [pscustomobject]@{ Category = Get-DriverCategory $name; Name = $name; Version = $ver; Date = ConvertTo-IsoDate $r.Text[3]
                                   Url = if ($url) { $url -replace ' ', '%20' } else { $null } }
            }
        }
        break
    }
    if (-not $res.PageUrl) {
        $res.PageUrl = "https://www.asrock.com/MB/$platform/$enc/index.asp"; $res.BiosPageUrl = "$($res.PageUrl)#BIOS"
        $res.Status = 'Could not read BIOS list'
        $res.Note = if (@($script:HttpNotes | Where-Object { $_.Source -eq 'ASRock BIOS' -and $_.Message -match 'bot protection' }).Count) {
            "ASRock's website blocked the automatic check this time (bot protection). Open the BIOS page link to compare by hand, or run the scan again later."
        } else { 'Open the BIOS page link to check manually.' }
    }
    return @{ Board = $res; Drivers = @($drivers) }
}

# --- MSI --------------------------------------------------------------------
function Get-MsiBoard($product, $isLaptop, $osTag) {
    $boardId = if ($product -match '\(MS-(\w+)\)') { $Matches[1] } else { $null }
    $name = ($product -replace '\s*\(MS-\w+\)\s*$', '').Trim()
    $slug = $name -replace '\s+', '-'
    $res = New-BiosResult 'MSI' $name
    $line = if ($isLaptop) { 'Laptop' } else { 'Motherboard' }
    $res.PageUrl = "https://www.msi.com/$line/$slug/support"; $res.BiosPageUrl = "$($res.PageUrl)#bios"
    $api = 'https://www.msi.com/api/v1/product/support/panel?product=' + [uri]::EscapeDataString($slug)
    $j = Invoke-Http "$api&type=bios" -Json -Source 'MSI BIOS'
    $drivers = @()
    if ($j -and $j.result -and $j.result.downloads) {
        $res.MatchedProduct = $slug
        $items = foreach ($p in $j.result.downloads.PSObject.Properties) { if ($p.Name -notin @('type_title', 'os')) { $p.Value } }
        $entries = @($items | Where-Object { $_.download_version } | ForEach-Object {
            [pscustomobject]@{ Version = ($_.download_version -replace '\s*\(Beta.*\)', '').Trim(); IsBeta = ($_.download_version -match '(?i)beta')
                               Date = ConvertTo-IsoDate $_.download_release; Size = $null
                               Notes = ConvertFrom-HtmlText $_.download_description; Url = $_.download_url }
        } | Sort-Object Date -Descending)
        # MSI: SMBIOS shows e.g. "A.L2" / "1.A0"; the site lists "7C91vAL2"
        $norm = { param($v) $x = ([string]$v).ToUpper(); if ($x -match 'V([0-9A-Z]+)$') { $x = $Matches[1] }; ($x -replace '[^0-9A-Z]', '') }
        if ($entries.Count) { Set-BiosStatus $res $script:Audit.System.BIOS.Version $entries $norm $false }
        if ($boardId -and $entries.Count -and -not ($entries[0].Version -like "$boardId*")) { $res.Note = "BIOS file names don't start with board ID $boardId - check the product match." }

        $os = if ($osTag -eq '11') { 'Win11 64' } else { 'Win10 64' }
        $d = Invoke-Http "$api&type=driver&os=$([uri]::EscapeDataString($os))" -Json -Source 'MSI drivers'
        if ($d -and $d.result -and $d.result.downloads) {
            $drivers = foreach ($p in $d.result.downloads.PSObject.Properties) {
                if ($p.Name -in @('type_title', 'os')) { continue }
                foreach ($it in @($p.Value)) {
                    $n = if ($it.download_title) { $it.download_title } else { $p.Name }
                    [pscustomobject]@{ Category = Get-DriverCategory "$($p.Name) $n"; Name = $n; Version = $it.download_version
                                       Date = ConvertTo-IsoDate $it.download_release; Url = $it.download_url }
                }
            }
        }
    } else { $res.Status = 'Could not read BIOS list'; $res.Note = "No MSI product found for '$slug'. Open the support page and search for the model." }
    return @{ Board = $res; Drivers = @($drivers) }
}

# --- ASUS -------------------------------------------------------------------
function Get-AsusBoard($model, $osTag) {
    $res = New-BiosResult 'ASUS' $model
    $enc = [uri]::EscapeDataString($model)
    $res.PageUrl = "https://www.asus.com/supportonly/$enc/HelpDesk_Download/"; $res.BiosPageUrl = "https://www.asus.com/supportonly/$enc/HelpDesk_BIOS/"
    $fix = { param($u) if ($u -and $u -like '/*') { 'https://dlcdnets.asus.com' + $u } else { $u } }
    $j = Invoke-Http "https://www.asus.com/support/webapi/ProductV2/GetPDBIOS?website=global&model=$enc&cpu=" -Json -Source 'ASUS BIOS'
    if (-not ($j -and $j.Result -and $j.Result.Obj)) { $j = Invoke-Http "https://www.asus.com/support/api/product.asmx/GetPDBIOS?website=global&model=$enc&cpu=" -Json -Source 'ASUS BIOS' }
    $drivers = @()
    if ($j -and $j.Result -and $j.Result.Obj) {
        $res.MatchedProduct = $model
        $files = @($j.Result.Obj | Where-Object { $_.Name -match '(?i)BIOS' } | ForEach-Object { $_.Files })
        if (-not $files.Count) { $files = @($j.Result.Obj | ForEach-Object { $_.Files }) }
        $entries = @($files | ForEach-Object {
            [pscustomobject]@{ Version = [string]$_.Version; IsBeta = ([string]$_.Title -match '(?i)beta'); Date = ConvertTo-IsoDate $_.ReleaseDate; Size = $_.FileSize
                               Notes = ConvertFrom-HtmlText $_.Description; Url = & $fix $_.DownloadUrl.Global }
        } | Sort-Object Date -Descending)
        $norm = { param($v) $x = [string]$v; if ($x -match '(\d+)\s*$') { $Matches[1] } else { $x } }
        if ($entries.Count) { Set-BiosStatus $res $script:Audit.System.BIOS.Version $entries $norm }

        $osid = if ($osTag -eq '11') { 52 } else { 45 }
        $d = Invoke-Http "https://www.asus.com/support/webapi/ProductV2/GetPDDrivers?website=global&model=$enc&cpu=&osid=$osid" -Json -Source 'ASUS drivers'
        if ($d -and $d.Result -and $d.Result.Obj) {
            $drivers = foreach ($g in $d.Result.Obj) {
                foreach ($f in @($g.Files)) {
                    [pscustomobject]@{ Category = Get-DriverCategory "$($g.Name) $($f.Title)"; Name = [string]$f.Title; Version = [string]$f.Version
                                       Date = ConvertTo-IsoDate $f.ReleaseDate; Url = & $fix $f.DownloadUrl.Global }
                }
            }
        }
    } else { $res.Status = 'Could not read BIOS list'; $res.Note = 'Open the BIOS page link to check manually.' }
    return @{ Board = $res; Drivers = @($drivers) }
}

# --- Gigabyte ---------------------------------------------------------------
function Get-GigabyteBoard($product, $boardVersion) {
    $res = New-BiosResult 'Gigabyte' $product
    $base = (([string]$product) -replace '(?i)\s*\(rev\.?[^)]*\)\s*$', '').Trim()
    # Until the product is found, link to a search for its support page rather than Gigabyte's front page
    $res.PageUrl = New-SearchUrl "site:gigabyte.com `"$base`" support"; $res.BiosPageUrl = $res.PageUrl
    $api = 'https://www.gigabyte.com/iisApplicationNuxt/api/proxy/api/v1.0'
    $drivers = @()
    $list = Invoke-Http "$api/Support/global/DownloadCenter/2/GetProducts" -Json -Source 'Gigabyte product list' -Quiet
    if (-not ($list -and $list.data)) {
        # Second try with cookies from the main site (some regions get a cookie check first)
        $sess = $null
        try { $null = Invoke-WebRequest 'https://www.gigabyte.com/Support' -UseBasicParsing -UserAgent $script:BrowserUA -TimeoutSec 30 -SessionVariable sess -ErrorAction Stop } catch {}
        $list = Invoke-Http "$api/Support/global/DownloadCenter/2/GetProducts" -Json -Source 'Gigabyte product list' -Session $sess
    }
    if (-not ($list -and $list.data)) {
        $res.Status = 'Could not read BIOS list'
        $res.Note = "Gigabyte's product list could not be loaded (see Lookup problems). Use the link to find the support page for $base."
        return @{ Board = $res; Drivers = @() }
    }
    # Gigabyte names products like "B650 GAMING X AX (rev. 1.0/1.1/1.2)" - one entry can cover several board revisions
    $revRx = '(?i)^(.*?)\s*\(rev\.?\s*([\d\.]+(?:\s*/\s*[\d\.]+)*)\)\s*$'
    $parse = { param($n) $n = ([string]$n).Trim(); if ($n -match $revRx) { [pscustomobject]@{ Base = $Matches[1].Trim(); Revs = @($Matches[2] -split '\s*/\s*') } } else { [pscustomobject]@{ Base = $n; Revs = @() } } }
    $cands = @($list.data | Where-Object { (& $parse $_.productName).Base -ieq $base })
    if (-not $cands.Count) {
        $res.Status = 'Could not read BIOS list'
        $res.Note = "Gigabyte's product list has no board named '$base'. Use the link to find its support page."
        return @{ Board = $res; Drivers = @() }
    }
    $knownRev = ([string]$boardVersion).Trim() -match '^\d+(\.\d+)?$'
    $pick = $null
    if ($knownRev) {
        $want = ([string]$boardVersion).Trim(); if ($want -notmatch '\.') { $want += '.0' }
        $pick = $cands | Where-Object { (& $parse $_.productName).Revs -contains $want } | Select-Object -First 1
    }
    if (-not $pick) { $pick = $cands[0] }
    $slugOf = { param($n) $p = & $parse $n; $b = $p.Base -replace '\s+', '-'; if ($p.Revs.Count) { $b + '-rev-' + (($p.Revs | ForEach-Object { $_ -replace '\.', '' }) -join '-') } else { $b } }
    $res.Revisions = @($cands | ForEach-Object { [pscustomobject]@{ Name = $_.productName; Url = "https://www.gigabyte.com/Motherboard/$(& $slugOf $_.productName)/support" } })
    if ($cands.Count -gt 1 -and -not ($knownRev -and $pick -and ((& $parse $pick.productName).Revs -contains $want))) {
        $res.Note = "This board exists in $($cands.Count) revision groups ($(($cands | ForEach-Object { ($_.productName -replace '(?i)^.*\(rev\.?\s*', '') -replace '\)$', '' }) -join '; ')) and Windows doesn't report which one this is. Check the 'REV' sticker on the board before using a BIOS file - revisions can need different BIOS files. Showing $($pick.productName)."
    }
    $res.MatchedProduct = $pick.productName
    $res.PageUrl = "https://www.gigabyte.com/Motherboard/$(& $slugOf $pick.productName)/support"; $res.BiosPageUrl = "$($res.PageUrl)#support-dl-bios"
    $tab = Invoke-Http "$api/Consumer/global/GetProductTabDataAsync/Support/$($pick.productId)" -Json -Source 'Gigabyte downloads'
    if ($tab -and $tab.data) {
        $dlNode = @($tab.data | Where-Object { $_.key -eq 'download' })[0]
        $bios = @($dlNode.child | Where-Object { $_.key -eq 'bios' })[0].data
        $drv  = @($dlNode.child | Where-Object { $_.key -eq 'driver' })[0].data
        $entries = @(@($bios) | Where-Object { $_.fileVersion } | ForEach-Object {
            [pscustomobject]@{ Version = $_.fileVersion; IsBeta = ($_.fileVersion -cmatch '^F\d+[a-z]+$'); Date = ConvertTo-IsoDate $_.fileReleaseDate; Size = $_.fileSize
                               Notes = ConvertFrom-HtmlText $_.fileDescription; Url = $_.filePath }
        } | Sort-Object Date -Descending)
        $norm = { param($v) ([string]$v).Trim().ToUpper() }
        if ($entries.Count) {
            Set-BiosStatus $res $script:Audit.System.BIOS.Version $entries $norm
            if ($res.Status -eq 'Compare manually' -or $res.Status -eq 'Up to date') {
                # Installed might be a beta (F19d) - compare by number
                $ni = Get-NumericVersion $script:Audit.System.BIOS.Version; $nl = Get-NumericVersion $res.Latest.Version
                if ($ni -and $nl -and [int]$nl -gt [int]$ni) { $res.Status = 'Newer version available' }
            }
        }
        $drivers = @(@($drv) | Where-Object { $_.fileVersion } | ForEach-Object {
            [pscustomobject]@{ Category = Get-DriverCategory $_.fileDescription; Name = $_.fileDescription; Version = $_.fileVersion
                               Date = ConvertTo-IsoDate $_.fileReleaseDate; Url = $_.filePath }
        })
    }
    return @{ Board = $res; Drivers = @($drivers) }
}

# --- NVIDIA -----------------------------------------------------------------
function ConvertTo-NvidiaVersion([string]$winVer) {
    $d = ($winVer -replace '[^\d]', '')
    if ($d.Length -lt 5) { return $null }
    $l = $d.Substring($d.Length - 5)
    return '{0}.{1}' -f $l.Substring(0, 3), $l.Substring(3)
}
function Get-NvidiaLatest($gpuName, $osTag) {
    if (-not $script:NvLookup) {
        $x = Invoke-Http 'https://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=3' -Source 'NVIDIA product list'
        $script:NvLookup = @()
        if ($x) {
            $script:NvLookup = @([regex]::Matches($x, '(?s)<LookupValue\s+ParentID="(\d+)"[^>]*>\s*<Name>([^<]+)</Name>\s*<Value>(\d+)</Value>') |
                ForEach-Object { [pscustomobject]@{ Psid = $_.Groups[1].Value; Name = ([System.Net.WebUtility]::HtmlDecode($_.Groups[2].Value) -replace '^NVIDIA\s+', '').Trim(); Pfid = $_.Groups[3].Value } })
        }
    }
    $n = ($gpuName -replace '^NVIDIA\s+', '').Trim()
    $hit = $script:NvLookup | Where-Object { $_.Name -ieq $n } | Select-Object -First 1
    if (-not $hit) { $n2 = $n -replace '\s+\d+\s*GB$', ''; $hit = $script:NvLookup | Where-Object { $_.Name -ieq $n2 } | Select-Object -First 1 }
    if (-not $hit) { return $null }
    $os = if ($osTag -eq '11') { 135 } else { 57 }
    $j = Invoke-Http "https://gfwsl.geforce.com/services_toolkit/services/com/nvidia/services/AjaxDriverService.php?func=DriverManualLookup&psid=$($hit.Psid)&pfid=$($hit.Pfid)&osID=$os&languageCode=1033&isWHQL=1&dch=1&sort1=0&numberOfResults=1" -Json -Source 'NVIDIA driver'
    if (-not ($j -and $j.IDS)) { return $null }
    $di = $j.IDS[0].downloadInfo
    return [pscustomobject]@{ Version = [string]$di.Version; Date = ConvertTo-IsoDate $di.ReleaseDateTime; Name = [uri]::UnescapeDataString([string]$di.Name)
                              DetailsUrl = [string]$di.DetailsURL; DownloadUrl = [string]$di.DownloadURL }
}


# --- Microsoft Update Catalog ---------------------------------------------
$script:CatalogBuilds = @{ '21H2' = 22000; '22H2' = 22621; '23H2' = 22631; '24H2' = 26100; '25H2' = 26200; '26H1' = 28000 }
$script:CatalogCodenames = @{ 'Threshold' = 10240; 'Redstone' = 14393; 'Vibranium' = 19041; 'Manganese' = 19041; 'Iron' = 20348; 'Cobalt' = 22000; 'Nickel' = 22621; 'Germanium' = 26100 }

function Get-CatalogResults([string]$Query) {
    $url = 'https://www.catalog.update.microsoft.com/Search.aspx?q=' + [uri]::EscapeDataString($Query) + '&scol=DateComputed&sdir=desc'
    $html = Invoke-Http $url -Source 'MS Catalog'
    if (-not $html) { return @() }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($row in [regex]::Matches($html, '(?s)<tr\s+id="([0-9a-fA-F\-]{36})_R\d+".*?</tr>')) {
        $cells = @{}
        foreach ($c in [regex]::Matches($row.Value, '(?s)<td[^>]*\sid="[0-9a-fA-F\-]{36}_C(\d+)_R\d+"[^>]*>(.*?)</td>')) { $cells[[int]$c.Groups[1].Value] = ConvertFrom-HtmlText $c.Groups[2].Value }
        if (-not $cells.ContainsKey(5)) { continue }
        $id = $row.Groups[1].Value
        $out.Add([pscustomobject]@{ Id = $id; Title = $cells[1]; Products = $cells[2]; Classification = $cells[3]
            Date = ConvertTo-IsoDate $cells[4]; Version = $cells[5]; Size = $cells[6]; ExactBoard = $false
            Url = "https://www.catalog.update.microsoft.com/ScopedViewInline.aspx?updateid=$id" })
    }
    return , $out.ToArray()
}

# The Catalog's Download button posts the update ID to DownloadDialog.aspx, which answers with the direct .cab URL(s)
function Get-CatalogDownloadUrl([string]$UpdateId) {
    $body = @{ updateIDs = ('[{"size":0,"languages":"","uidInfo":"' + $UpdateId + '","updateID":"' + $UpdateId + '"}]') }
    try {
        $r = Invoke-WebRequest -Uri 'https://www.catalog.update.microsoft.com/DownloadDialog.aspx' -Method Post -Body $body -ContentType 'application/x-www-form-urlencoded' `
             -UserAgent $script:BrowserUA -UseBasicParsing -TimeoutSec 40 -ErrorAction Stop
        $m = [regex]::Matches([string]$r.Content, "\.url\s*=\s*'(https?://[^']+)'")
        if ($m.Count) { return $m[0].Groups[1].Value }
    } catch {
        $script:HttpNotes.Add([pscustomobject]@{ Source = 'MS Catalog download link'; Url = $UpdateId; Message = $_.Exception.Message })
    }
    return $null
}

function Test-CatalogApplicable([string]$Products, [int]$Build, [bool]$IsW11) {
    if (-not $Products) { return $true }
    $ok = $false; $sawClient = $false
    foreach ($m in [regex]::Matches($Products, '(?i)Windows (10|11)(?: Client)?(?: S)?,\s*(?:version\s+)?([\w\.]+)\s+and later')) {
        $sawClient = $true
        $os = $m.Groups[1].Value; $tag = $m.Groups[2].Value
        if ($os -eq '11' -and -not $IsW11) { continue }
        $min = $null
        if ($script:CatalogBuilds.ContainsKey($tag.ToUpper())) { $min = $script:CatalogBuilds[$tag.ToUpper()] }
        elseif ($script:CatalogCodenames.ContainsKey($tag)) { $min = $script:CatalogCodenames[$tag] }
        elseif ($tag -match '^\d{4}$') { $min = @{ '1507' = 10240; '1511' = 10586; '1607' = 14393; '1703' = 15063; '1709' = 16299; '1803' = 17134; '1809' = 17763; '1903' = 18362; '1909' = 18363; '2004' = 19041 }[$tag] }
        if (-not $min -or $Build -ge $min) { $ok = $true }
    }
    if (-not $sawClient) { $ok = ($Products -match '(?i)Windows 1[01]') -and ($Products -notmatch '(?i)^\s*Windows Server') }
    return $ok
}

function Get-CatalogVerdict($dev, $entries, [string]$query) {
    $v = [ordered]@{ Query = $query; SearchUrl = (New-CatalogUrl $query); Installed = $dev.Version
                     FamilyLatest = $null; NewestOverall = $null; ExactBoardLatest = $null; Status = 'Not found in Catalog'; Count = @($entries).Count }
    if (-not @($entries).Count) { return [pscustomobject]$v }
    $sorted = @($entries | Sort-Object @{e={ $_.Date }; Descending = $true}, @{e={ [string](Get-NumericVersion $_.Version) }; Descending = $true})
    $pick = { param($list) ($list | Sort-Object @{e={ $_.Date }; Descending = $true} | Select-Object -First 1) }
    $v.NewestOverall = $sorted[0]
    $exact = @($entries | Where-Object { $_.ExactBoard }); if ($exact.Count) { $v.ExactBoardLatest = & $pick $exact }
    $isGeneric = ($dev.Provider -match '^Microsoft') -or -not $dev.Version
    if ($isGeneric) { $v.Status = 'Vendor driver available'; return [pscustomobject]$v }
    $maj = ((Get-NumericVersion $dev.Version) -split '\.')[0]
    # Same driver family: same major version, or yearly bumps of a small major (Intel 22 -> 24, NVIDIA 31 -> 32).
    # A jump like Realtek 10.x -> 1125.x is a different driver branch.
    $sameFam = { param($ver) $m = ((Get-NumericVersion $ver) -split '\.')[0]; if (-not $m -or -not $maj) { $false } elseif ($m -eq $maj) { $true } else { ([int64]$m -lt 100 -and [int64]$maj -lt 100 -and [Math]::Abs([int64]$m - [int64]$maj) -le 3) } }
    $fam = @($entries | Where-Object { & $sameFam $_.Version })
    if ($fam.Count) {
        # newest = highest version within the family (dates can be re-publications)
        $best = $fam[0]
        foreach ($e in $fam) { if ((Compare-NumericVersion $e.Version $best.Version) -gt 0) { $best = $e } }
        $v.FamilyLatest = $best
        $c = Compare-NumericVersion $best.Version $dev.Version
        if ($c -gt 0) { $v.Status = 'Newer version available' } else { $v.Status = 'Up to date' }
    } else { $v.Status = 'Up to date' }
    if ($v.Status -eq 'Up to date' -and $v.NewestOverall -and -not (& $sameFam $v.NewestOverall.Version) -and $dev.Date -and $v.NewestOverall.Date -gt $dev.Date) {
        $v.Status = 'Newer driver branch available'
    }
    return [pscustomobject]$v
}

# --- AMD: chipset driver and graphics auto-detect installer, straight from amd.com ---
function Get-AmdChipsetDriver([string]$boardProduct) {
    $m = [regex]::Match($boardProduct, '(?i)\b([ABX])(\d)(\d{2})(E?)\b')
    if (-not $m.Success) { return $null }
    $series = [int]$m.Groups[2].Value
    $socket = if ($series -ge 6) { 'am5' } elseif ($series -ge 3) { 'am4' } else { return $null }
    $chip = ($m.Groups[1].Value + $m.Groups[2].Value + $m.Groups[3].Value + $m.Groups[4].Value).ToLower()
    $page = "https://www.amd.com/en/support/downloads/drivers.html/chipsets/$socket/$chip.html"
    $html = Invoke-Http $page -Source 'AMD chipset'
    if (-not $html) { return $null }
    $l = [regex]::Match($html, 'https://drivers\.amd\.com/drivers/amd_chipset_software_([\d\.]+)\.exe')
    if (-not $l.Success) { return $null }
    return [pscustomobject]@{ Version = $l.Groups[1].Value; Url = $l.Value; PageUrl = $page }
}
function Get-AmdGraphicsInstaller {
    $html = Invoke-Http 'https://www.amd.com/en/support/download/drivers.html' -Source 'AMD graphics'
    if (-not $html) { return $null }
    $l = [regex]::Match($html, 'https://drivers\.amd\.com/drivers/installer/[^"''\s<>]+?adrenalin-edition-([\d\.]+)-minimalsetup[^"''\s<>]*\.exe')
    if (-not $l.Success) { return $null }
    return [pscustomobject]@{ Version = $l.Groups[1].Value; Url = $l.Value }
}

if (-not $Offline) {
Invoke-Section 'Online: manufacturer BIOS, drivers and part links' {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}
    $osTag = if ($script:Audit.Windows -and $script:Audit.Windows.IsWindows11) { '11' } else { '10' }

    # Installed driver packages (chipset software etc. have no single device driver version)
    $re = '(?i)driver|chipset|realtek|intel|amd|nvidia|bluetooth|wireless|wi-fi|ethernet|lan|audio|graphics|raid|serial io|management engine|killer|qualcomm|mediatek'
    $script:DriverPrograms = @(@(foreach ($k in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
        Get-ItemProperty $k -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -and $_.DisplayName -match $re -and -not $_.SystemComponent } | ForEach-Object {
            $idate = $null; if ($_.InstallDate -match '^(\d{4})(\d{2})(\d{2})$') { $idate = "$($Matches[1])-$($Matches[2])-$($Matches[3])" }
            [pscustomobject]@{ Name = [string]$_.DisplayName; Version = [string]$_.DisplayVersion; Publisher = [string]$_.Publisher; InstallDate = $idate }
        }
    }) | Sort-Object Name -Unique)

    $S = $script:Audit.System
    $cpuVendor = if (($script:Audit.Hardware.CPU | Select-Object -First 1).Manufacturer -match 'AMD') { 'AMD' } else { 'Intel' }
    $isLaptop = $S.Chassis -match 'Laptop|Notebook|Portable|Convertible|Detachable|Tablet|Sub-notebook'
    $result = $null
    switch ($S.Vendor) {
        'ASRock'   { $result = Get-AsrockBoard $S.Board.Product $cpuVendor $osTag }
        'MSI'      { $p = if ($S.IsCustomBuild -or -not $isLaptop) { $S.Board.Product } else { $S.SystemModel }; $result = Get-MsiBoard $p $isLaptop $osTag }
        'ASUS'     { $result = Get-AsusBoard (($S.Board.Product -replace '\s+$', '')) $osTag }
        'Gigabyte' { $result = Get-GigabyteBoard $S.Board.Product $S.Board.Version }
    }
    $board = $null; $offers = @()
    if ($result) {
        $board = $result.Board
        $offers = @(Select-NewestOffers $result.Drivers | ForEach-Object {
            $o = $_
            $inst = if ($o.Category -in @('Utility', 'Other')) { $null } else { Find-InstalledFor $o.Category $o.Name }
            [pscustomobject][ordered]@{ Category = $o.Category; Name = $o.Name; Version = $o.Version; Date = $o.Date; Url = $o.Url
                InstalledName = $(if ($inst) { $inst.Name }); InstalledVersion = $(if ($inst) { $inst.Version }); InstalledDate = $(if ($inst) { $inst.Date })
                Status = $(if ($o.Category -in @('Utility', 'Other')) { 'Optional software' } else { Get-OfferStatus $o.Version $o.Date $inst }) }
        })
    }
    if ($cpuVendor -eq 'AMD') {
        $amdChip = Get-AmdChipsetDriver ([string]$S.Board.Product)
        if ($amdChip) {
            $inst = Find-InstalledFor 'Chipset / platform' 'AMD chipset'
            $offers = @($offers) + [pscustomobject][ordered]@{ Category = 'Chipset / platform'; Name = 'AMD Chipset Software (from AMD)'; Version = $amdChip.Version; Date = $null; Url = $amdChip.Url
                InstalledName = $(if ($inst) { $inst.Name }); InstalledVersion = $(if ($inst) { $inst.Version }); InstalledDate = $(if ($inst) { $inst.Date })
                Status = (Get-OfferStatus $amdChip.Version $null $inst); Source = 'AMD'; PageUrl = $amdChip.PageUrl }
        }
    }
    if (-not $result) {
        $board = New-BiosResult $S.Vendor $S.FriendlyModel
        $board.Status = 'No automatic lookup for this maker yet'
        $board.PageUrl = ($S.SupportLinks | Select-Object -First 1).Url
        $board.Installed = $S.BIOS.Version
        $board.Note = 'Use the support link; Dell, HP and Lenovo catalog lookups are planned.'
    }

    # Graphics cards
    $gpus = foreach ($g in @($script:Audit.Hardware.GPU)) {
        $o = [ordered]@{ Name = $g.Name; InstalledVersion = $g.DriverVersion; InstalledDate = $g.DriverDate; VendorVersion = $null
                         Latest = $null; Status = 'Not checked'; Links = @() }
        if ($g.PNPDeviceID -match 'VEN_10DE') {
            $o.VendorVersion = ConvertTo-NvidiaVersion $g.DriverVersion
            $l = Get-NvidiaLatest $g.Name $osTag
            if ($l) {
                $o.Latest = $l
                $c = Compare-NumericVersion $l.Version $o.VendorVersion
                $o.Status = if ($c -gt 0) { 'Newer available' } elseif ($c -eq 0) { 'Up to date' } else { 'Installed is newer' }
                $o.Links = @([pscustomobject]@{ Label = 'Driver details'; Url = $l.DetailsUrl }, [pscustomobject]@{ Label = 'Download'; Url = $l.DownloadUrl })
            } else { $o.Status = 'Could not look up'; $o.Links = @([pscustomobject]@{ Label = 'NVIDIA drivers'; Url = 'https://www.nvidia.com/en-us/drivers/' }) }
        } elseif ($g.PNPDeviceID -match 'VEN_1002') {
            $o.Links = @([pscustomobject]@{ Label = 'AMD drivers'; Url = 'https://www.amd.com/en/support/download/drivers.html' })
            $a = Get-AmdGraphicsInstaller
            if ($a) {
                $o.Latest = [pscustomobject]@{ Version = $a.Version; Date = $null; Name = 'AMD Software: Adrenalin Edition (auto-detect installer)'; DownloadUrl = $a.Url; DetailsUrl = 'https://www.amd.com/en/support/download/drivers.html' }
                $o.Status = 'Check with AMD installer'
            } else { $o.Status = 'Check on AMD site' }
        } elseif ($g.PNPDeviceID -match 'VEN_8086') {
            $o.Status = 'Check with Intel tool'; $o.Links = @([pscustomobject]@{ Label = 'Intel Driver & Support Assistant'; Url = 'https://www.intel.com/content/www/us/en/support/detect.html' })
        }
        [pscustomobject]$o
    }

    # Parts list with direct / search links
    $site = { param($domain, $q) 'https://www.google.com/search?q=' + [uri]::EscapeDataString("site:$domain $q") }
    $parts = New-Object System.Collections.Generic.List[object]
    $parts.Add([pscustomobject]@{ Part = 'Motherboard / system'; Model = "$($S.Vendor) $($S.FriendlyModel)"; Links = @(
        @([pscustomobject]@{ Label = 'Product support page'; Url = $board.PageUrl }) + @(if ($board.BiosPageUrl -and $board.BiosPageUrl -ne $board.PageUrl) { [pscustomobject]@{ Label = 'BIOS downloads'; Url = $board.BiosPageUrl } }) | Where-Object { $_.Url }) })
    foreach ($c in @($script:Audit.Hardware.CPU)) {
        $dom = if ($c.Manufacturer -match 'AMD') { 'amd.com' } else { 'intel.com' }
        $parts.Add([pscustomobject]@{ Part = 'Processor'; Model = $c.Name; Links = @([pscustomobject]@{ Label = "Find on $dom"; Url = (& $site $dom ($c.Name -replace '\s+\d+-Core Processor', '' -replace '\(R\)|\(TM\)|CPU|@.*$', '')) }) })
    }
    foreach ($g in @($gpus)) { $parts.Add([pscustomobject]@{ Part = 'Graphics'; Model = $g.Name; Links = @($g.Links) }) }
    $mem = @($script:Audit.Hardware.Memory) | Where-Object { $_.PartNumber } | Group-Object PartNumber
    foreach ($m in $mem) { $parts.Add([pscustomobject]@{ Part = "Memory ($($m.Count) x $($m.Group[0].CapacityGB) GB)"; Model = "$($m.Group[0].Manufacturer) $($m.Name)"; Links = @([pscustomobject]@{ Label = 'Search part number'; Url = (New-SearchUrl "$($m.Name) $($m.Group[0].Manufacturer)") }) }) }
    foreach ($d in @($script:Audit.Hardware.Disks)) { $parts.Add([pscustomobject]@{ Part = "Disk ($($d.BusType) $($d.MediaType))"; Model = "$($d.Name) - firmware $($d.Firmware)"; Links = @($d.Links) }) }
    foreach ($n in @($script:DeviceList | Where-Object { $_.Present -and $_.Class -in @('Net', 'Bluetooth') -and $_.Bus -match '^(PCI|USB)$' -and $_.Provider -notmatch '^Microsoft' })) {
        $parts.Add([pscustomobject]@{ Part = $(if ($n.Class -eq 'Net') { 'Network' } else { 'Bluetooth' }); Model = "$($n.Name) - driver $($n.Version)"; Links = @($n.Links | Select-Object -First 3) })
    }
    foreach ($a in @($script:DeviceList | Where-Object { $_.Present -and $_.Class -eq 'MEDIA' -and $_.Bus -match 'HDAUDIO|INTELAUDIO' -and $_.Name -notmatch '(?i)NVIDIA|AMD High Definition|Display Audio|HDMI' })) {
        $parts.Add([pscustomobject]@{ Part = 'Audio'; Model = "$($a.Name) - driver $($a.Version)"; Links = @($a.Links | Select-Object -First 3) })
    }


    # ---------------- Microsoft Update Catalog: newest drivers per chip ----------------
    if (-not $SkipCatalog) {
        $build = [int]$script:Audit.Windows.Build; $isW11 = [bool]$script:Audit.Windows.IsWindows11
        $cands = @($script:DeviceList | Where-Object { $_.Present -and $_.IsHardware -and $_.CatalogQuery -and $_.Class -ne 'Firmware' -and
                    ($_.Provider -notmatch '^Microsoft' -or ($_.Flags -contains 'GenericDriver') -or ($_.Flags -contains 'NoDriver') -or ($_.Flags -contains 'Problem')) })
        $byQuery = @{}
        foreach ($d in $cands) { if (-not $byQuery.ContainsKey($d.CatalogQuery)) { $byQuery[$d.CatalogQuery] = New-Object System.Collections.Generic.List[object] }; $byQuery[$d.CatalogQuery].Add($d) }
        $n = 0
        foreach ($q in @($byQuery.Keys)) {
            $n++
            Write-Host ("    MS Catalog {0}/{1}: {2}" -f $n, $byQuery.Count, $q) -ForegroundColor DarkGray
            $all = @{}
            $queries = @($q, "$q `"Windows $(if ($isW11) { '11' } else { '10' })`"", "$q Vibranium")
            $exact = ($byQuery[$q] | Where-Object { $_.CatalogExactQuery } | Select-Object -First 1).CatalogExactQuery
            if ($exact) { $queries += $exact }
            foreach ($qq in $queries) {
                foreach ($e in (Get-CatalogResults $qq)) {
                    if (-not $e -or -not $e.Id) { continue }
                    if (-not $all.ContainsKey($e.Id)) { $e | Add-Member -NotePropertyName ExactBoard -NotePropertyValue ($qq -eq $exact) -Force; $all[$e.Id] = $e }
                    elseif ($qq -eq $exact) { $all[$e.Id].ExactBoard = $true }
                }
            }
            $entries = @($all.Values | Where-Object { $_.Version -and $_.Version -ne 'n/a' -and (Test-CatalogApplicable $_.Products $build $isW11) })
            foreach ($d in $byQuery[$q]) {
                $d.Catalog = Get-CatalogVerdict $d $entries $q
                if ($d.Catalog.Status -in @('Newer version available', 'Vendor driver available', 'Newer driver branch available')) {
                    foreach ($e in @($d.Catalog.FamilyLatest, $d.Catalog.NewestOverall, $d.Catalog.ExactBoardLatest)) {
                        if ($e -and -not $e.PSObject.Properties['DownloadUrl']) { $e | Add-Member -NotePropertyName DownloadUrl -NotePropertyValue (Get-CatalogDownloadUrl $e.Id) -Force }
                    }
                }
            }
        }
        $script:Audit.Devices = @($script:DeviceList | Sort-Object @{e={ -not $_.IsHardware }}, Class, Name)
    }

    # ---------------- Downloadable actions (used by the PC Audit app's Download buttons) ----------------
    $actions = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $addAction = {
        param($target, $kind, $title, $url, $device, $ids, $from, $to, $signer, $source, $referer)
        if (-not $url -or $url -notmatch '^https://') { return }
        if ($seen.ContainsKey($url)) { $a = $seen[$url]; foreach ($i in @($ids)) { if ($i -and $a.InstanceIds -notcontains $i) { $a.InstanceIds += $i } }; $target | Add-Member -NotePropertyName ActionId -NotePropertyValue $a.Id -Force; return }
        $a = [pscustomobject][ordered]@{ Id = ('a' + ($actions.Count + 1)); Kind = $kind; Title = $title; Url = $url; Device = $device; InstanceIds = @($ids | Where-Object { $_ })
                                         FromVersion = $from; ToVersion = $to; ExpectedSigner = $signer; Source = $source; Referer = $referer }
        $actions.Add($a); $seen[$url] = $a
        $target | Add-Member -NotePropertyName ActionId -NotePropertyValue $a.Id -Force
    }
    if ($board -and $board.Latest -and $board.Latest.Url) {
        & $addAction $board.Latest 'bios' "$($board.Vendor) $($board.MatchedProduct) BIOS $($board.Latest.Version)" $board.Latest.Url "$($board.Vendor) $($board.MatchedProduct)" @() $board.Installed $board.Latest.Version $null $board.Vendor $null
    }
    foreach ($o in @($offers)) {
        if ($o.Url -and $o.Status -match '^(Newer|Probably newer|Generic|Compare manually|Not detected)') {
            $amd = $o.Url -match 'drivers\.amd\.com'
            & $addAction $o 'package' "$($o.Name) $($o.Version)" $o.Url $o.InstalledName @() $o.InstalledVersion $o.Version $(if ($amd) { 'Advanced Micro Devices' } else { $null }) $(if ($o.Source) { $o.Source } else { $board.Vendor }) $(if ($amd) { 'https://www.amd.com/' } else { $null })
        }
    }
    foreach ($d in @($script:DeviceList | Where-Object { $_.Catalog -and $_.Catalog.Status -in @('Newer version available', 'Vendor driver available', 'Newer driver branch available') })) {
        foreach ($e in @($d.Catalog.FamilyLatest, $d.Catalog.NewestOverall, $d.Catalog.ExactBoardLatest)) {
            if ($e -and $e.DownloadUrl -and ($d.Provider -match '^Microsoft' -or -not $d.Version -or (Compare-NumericVersion $e.Version $d.Version) -ne 0)) {
                & $addAction $e 'cab' "$($d.Name) driver $($e.Version)" $e.DownloadUrl $d.Name @($d.InstanceId) $d.Version $e.Version 'Microsoft' 'Microsoft Update Catalog' $null
            }
        }
    }
    foreach ($g in @($gpus)) {
        if ($g.Latest -and $g.Latest.DownloadUrl -and $g.Status -in @('Newer available', 'Check with AMD installer')) {
            $isAmd = $g.Latest.DownloadUrl -match 'amd\.com'
            & $addAction $g.Latest 'installer' "$($g.Name) - $($g.Latest.Name) $($g.Latest.Version)" $g.Latest.DownloadUrl $g.Name @() $g.VendorVersion $g.Latest.Version $(if ($isAmd) { 'Advanced Micro Devices' } else { 'NVIDIA Corporation' }) $(if ($isAmd) { 'AMD' } else { 'NVIDIA' }) $(if ($isAmd) { 'https://www.amd.com/' } else { $null })
        }
    }
    $script:Audit.Actions = $actions.ToArray()

    foreach ($n in $script:HttpNotes) { Write-Host "    [lookup] $($n.Source): $($n.Message)" -ForegroundColor DarkYellow }
    $script:Audit.Online = [ordered]@{
        Board = $board; BoardDrivers = $offers; GPUs = @($gpus); Parts = $parts.ToArray()
        DriverPrograms = $script:DriverPrograms; Notes = $script:HttpNotes.ToArray(); CheckedAt = Format-Time (Get-Date)
    }
}
}

# ---------------------------------------------------------------------------
# 12. Change history: compare with the previous scan of this PC, plus Windows' own driver-install record
# ---------------------------------------------------------------------------
function Get-UserDownloadsFolder {
    $mine = $null
    try { $mine = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path } catch {}
    if (-not $mine) { $up = if ($env:USERPROFILE) { $env:USERPROFILE } else { [Environment]::GetFolderPath('UserProfile') }; $mine = Join-Path $up 'Downloads' }
    try {
        $ex = Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" -ErrorAction Stop | Select-Object -First 1
        if ($ex) {
            $owner = Invoke-CimMethod -InputObject $ex -MethodName GetOwnerSid -ErrorAction Stop
            $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
            if ($owner.Sid -and $owner.Sid -ne $me) {
                $prof = Get-CimInstance Win32_UserProfile -Filter "SID='$($owner.Sid)'" -ErrorAction Stop
                if ($prof -and $prof.LocalPath -and (Test-Path (Join-Path $prof.LocalPath 'Downloads'))) { return (Join-Path $prof.LocalPath 'Downloads') }
            }
        }
    } catch {}
    return $mine
}

Invoke-Section 'Change history' {
    $now = Get-Date
    $changes = New-Object System.Collections.Generic.List[object]
    $sameVer = { param($a, $b) $na = Get-NumericVersion ([string]$a); $nb = Get-NumericVersion ([string]$b); ($na -and $nb -and ($na -eq $nb -or $na.EndsWith('.' + $nb) -or $nb.EndsWith('.' + $na))) }

    # Downloads and installs done through the PC Audit app
    $dlRoot = Join-Path (Get-UserDownloadsFolder) 'PC Audit'
    $dlLog = Join-Path (Join-Path $dlRoot $env:COMPUTERNAME) 'downloads.log'
    $downloads = @()
    if (Test-Path -LiteralPath $dlLog) {
        $downloads = @(Get-Content -LiteralPath $dlLog -Encoding UTF8 | ForEach-Object { try { $_ | ConvertFrom-Json } catch {} } | Where-Object { $_ })
    }

    # The previous scan of this PC (reports sit side by side as <PC>_<date> folders)
    $prev = $null; $prevInfo = $null
    $root = Split-Path $OutputDir -Parent
    if ($root -and (Test-Path -LiteralPath $root)) {
        $cand = Get-ChildItem -LiteralPath $root -Directory -Filter ("{0}_*" -f $env:COMPUTERNAME) -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -ne (Resolve-Path -LiteralPath $OutputDir).Path -and (Test-Path -LiteralPath (Join-Path $_.FullName 'audit.json')) } |
                Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($cand) {
            try {
                $prev = Get-Content -LiteralPath (Join-Path $cand.FullName 'audit.json') -Raw -Encoding UTF8 | ConvertFrom-Json
                $prevInfo = [ordered]@{ Date = (Format-Time $prev.Meta.Started); Folder = $cand.FullName; Version = $prev.Meta.Version }
            } catch { Add-Note 'Change history' "Previous scan could not be read: $($_.Exception.Message)" }
        }
    }
    $prevDate = $null; if ($prevInfo) { try { $prevDate = [datetime]$prevInfo.Date } catch {} }

    if ($prev) {
        $since = if ($prevDate) { $prevDate.ToString('yyyy-MM-dd') } else { 'the previous scan' }
        # Who caused a driver change? Check, in order: PC Audit's own installs, PC Audit's recommendations, Windows Update, Windows' install log
        $attribute = {
            param($instanceId, $name, $newVer, $prevDevice)
            $nvVer = $(if ($name -match 'NVIDIA' -and (Get-Command ConvertTo-NvidiaVersion -ErrorAction SilentlyContinue)) { ConvertTo-NvidiaVersion $newVer })
            $hit = @($downloads | Where-Object { $_.Ok -and $_.Stage -in @('Install', 'Launch') -and (($_.InstanceIds -contains $instanceId) -or (& $sameVer $_.ToVersion $newVer) -or ($nvVer -and (& $sameVer $_.ToVersion $nvVer))) }) | Select-Object -Last 1
            if ($hit) { return [pscustomobject]@{ Source = "Installed through PC Audit ($($hit.Source))"; ByPcAudit = $true; When = $hit.Time } }
            if ($prevDevice -and $prevDevice.Catalog) {
                foreach ($e in @($prevDevice.Catalog.FamilyLatest, $prevDevice.Catalog.NewestOverall, $prevDevice.Catalog.ExactBoardLatest)) {
                    if ($e -and (& $sameVer $e.Version $newVer)) { return [pscustomobject]@{ Source = "Recommended by PC Audit on $since (Microsoft Update Catalog)"; ByPcAudit = $true; When = $null } }
                }
            }
            foreach ($o in @($prev.Online.BoardDrivers)) {
                if ($o -and $o.InstalledName -eq $name -and (& $sameVer $o.Version $newVer)) { return [pscustomobject]@{ Source = "Recommended by PC Audit on $since (board maker)"; ByPcAudit = $true; When = $null } }
            }
            foreach ($g in @($prev.Online.GPUs)) {
                if ($g -and $g.Name -eq $name -and $g.Latest -and ((& $sameVer $g.Latest.Version $nvVer) -or (& $sameVer $g.Latest.Version $newVer))) { return [pscustomobject]@{ Source = "Recommended by PC Audit on $since (graphics maker)"; ByPcAudit = $true; When = $null } }
            }
            $wu = @($script:Audit.WindowsUpdate.History | Where-Object { $_.Category -eq 'Driver / firmware' -and $_.Result -like 'Succeeded*' -and $_.Title -like "*$newVer*" }) | Select-Object -First 1
            if ($wu) { return [pscustomobject]@{ Source = 'Windows Update'; ByPcAudit = $false; When = $wu.Date } }
            $si = @($script:DriverInstalls | Where-Object { $_.InstanceId -eq $instanceId -and (& $sameVer $_.Version $newVer) }) | Select-Object -First 1
            if ($si) { return [pscustomobject]@{ Source = $si.Method; ByPcAudit = $false; When = $si.Date } }
            return [pscustomobject]@{ Source = 'Other (not recommended by PC Audit)'; ByPcAudit = $false; When = $null }
        }

        $prevDevs = @{}
        foreach ($d in @($prev.Devices)) { if ($d.InstanceId) { $prevDevs[$d.InstanceId] = $d } }
        foreach ($d in @($script:DeviceList | Where-Object { $_.IsHardware -and $_.Present })) {
            $p = $prevDevs[$d.InstanceId]
            if (-not $p) {
                $changes.Add([pscustomobject][ordered]@{ Kind = 'Device added'; Item = $d.Name; From = $null; To = $d.Version; Source = $null; ByPcAudit = $false; When = $null })
                continue
            }
            if ($p.Version -and $d.Version -and $p.Version -ne $d.Version) {
                $a = & $attribute $d.InstanceId $d.Name $d.Version $p
                if (-not $a.When) {
                    $si = @($script:DriverInstalls | Where-Object { $_.InstanceId -eq $d.InstanceId -and (& $sameVer $_.Version $d.Version) }) | Select-Object -First 1
                    if ($si) { $a.When = $si.Date; if ($a.ByPcAudit) { $a.Source = "$($a.Source); installed by $($si.Method)" } }
                }
                $dir = if ((Compare-NumericVersion $d.Version $p.Version) -lt 0) { 'Driver rolled back' } else { 'Driver updated' }
                $changes.Add([pscustomobject][ordered]@{ Kind = $dir; Item = $d.Name; From = $p.Version; To = $d.Version; Source = $a.Source; ByPcAudit = $a.ByPcAudit; When = $a.When })
            }
            $wasBad = $p.Problem -and $p.Present; $isBad = [bool]$d.Problem
            if ($wasBad -and -not $isBad) { $changes.Add([pscustomobject][ordered]@{ Kind = 'Problem fixed'; Item = $d.Name; From = $p.Problem; To = 'Working'; Source = $null; ByPcAudit = $false; When = $null }) }
            if ($isBad -and -not $wasBad) { $changes.Add([pscustomobject][ordered]@{ Kind = 'New problem'; Item = $d.Name; From = 'Working'; To = $d.Problem; Source = $null; ByPcAudit = $false; When = $null }) }
        }
        $nowIds = @{}; foreach ($d in $script:DeviceList) { if ($d.Present) { $nowIds[$d.InstanceId] = $true } }
        foreach ($p in @($prev.Devices | Where-Object { $_.IsHardware -and $_.Present })) {
            if (-not $nowIds.ContainsKey($p.InstanceId)) { $changes.Add([pscustomobject][ordered]@{ Kind = 'Device removed'; Item = $p.Name; From = $p.Version; To = $null; Source = $null; ByPcAudit = $false; When = $null }) }
        }
        # BIOS
        $pb = [string]$prev.System.BIOS.Version; $nb = [string]$script:Audit.System.BIOS.Version
        if ($pb -and $nb -and $pb -ne $nb) {
            $src = 'Flashed outside Windows (BIOS updates are not logged by Windows)'; $by = $false
            $rec = $prev.Online.Board.Latest
            $dl = @($downloads | Where-Object { $_.Ok -and $_.Kind -eq 'bios' }) | Select-Object -Last 1
            $nbN = ($nb -replace '[^0-9A-Za-z]', '').ToUpper()
            if ($rec -and $nbN -and (([string]$rec.Version) -replace '[^0-9A-Za-z]', '').ToUpper().EndsWith($nbN)) { $src = "Recommended by PC Audit on $since"; $by = $true }
            if ($dl) { $src = "BIOS file downloaded through PC Audit on $(Format-Date $dl.Time)"; $by = $true }
            $changes.Add([pscustomobject][ordered]@{ Kind = 'BIOS updated'; Item = "$($script:Audit.System.Vendor) $($script:Audit.System.FriendlyModel)"; From = $pb; To = $nb; Source = $src; ByPcAudit = $by; When = $null })
        }
        # Windows build
        $pw = [string]$prev.Windows.FullBuild; $nw = [string]$script:Audit.Windows.FullBuild
        if ($pw -and $nw -and $pw -ne $nw) {
            $kind = if ($prev.Windows.Version -ne $script:Audit.Windows.Version) { 'Windows upgraded' } else { 'Windows updated' }
            $changes.Add([pscustomobject][ordered]@{ Kind = $kind; Item = "$($script:Audit.Windows.Product)"; From = "$($prev.Windows.Version) ($pw)"; To = "$($script:Audit.Windows.Version) ($nw)"; Source = 'Windows Update'; ByPcAudit = $false; When = $null })
        }
    }

    # Driver installs Windows recorded since the previous scan (or the last 90 days) that the comparison above didn't already explain
    $cut = if ($prevDate) { $prevDate } else { $now.AddDays(-90) }
    $recent = @($script:DriverInstalls | Where-Object { try { [datetime]$_.Date -ge $cut } catch { $false } })

    $script:Audit.History = [ordered]@{
        PreviousScan = $prevInfo; Changes = $changes.ToArray(); DriverInstalls = @($script:DriverInstalls); RecentInstallCount = $recent.Count
        Downloads = @($downloads | Select-Object -Last 200); DownloadsFolder = (Join-Path $dlRoot $env:COMPUTERNAME)
    }
}

# ---------------------------------------------------------------------------
# 13. Findings summary
# ---------------------------------------------------------------------------
Write-Step 'Building findings'
$findings = New-Object System.Collections.Generic.List[object]
# Keys: what the finding is about (event|..., wu|..., device|..., crashes, setupapi, rollback). Last: when it last happened.
# A dismissed finding stays hidden until it happens again after the dismissal. Without keys it is keyed by its title.
function Add-Finding($sev, $area, $title, $detail, $action, $keys = $null, $last = $null) {
    if (-not $keys) { $keys = @("finding|$area|$title") }
    $findings.Add([pscustomobject][ordered]@{ Severity = $sev; Area = $area; Title = $title; Detail = $detail; Action = $action; Keys = @($keys); Last = $last })
}

$W = $Audit.Windows
if ($W) {
    if ($W.SupportState -like 'OUT OF SUPPORT*') {
        $action = if ($W.IsWindows11) { 'Install the latest feature update (Settings > Windows Update), or use the Installation Assistant.' } else { 'Upgrade to Windows 11 if hardware allows, or enrol in Extended Security Updates.' }
        Add-Finding 'high' 'Windows' "$($W.Product) $($W.Version) no longer gets security updates" $W.SupportState $action
    }
    if ($W.PendingReboot.Count -gt 0) { Add-Finding 'medium' 'Windows' 'A restart is pending' ($W.PendingReboot -join '; ') 'Restart before troubleshooting further - pending installs can cause odd behaviour and block new updates.' }
    if ($W.UpdatePolicy.AutomaticUpdatesDisabled) { Add-Finding 'medium' 'Windows' 'Automatic updates disabled by policy' 'NoAutoUpdate policy is set.' 'Check whether this was intentional (registry tweak / debloat tool).' }
    if ($W.UpdatePolicy.ExcludeDriversFromWU) { Add-Finding 'info' 'Windows' 'Drivers are excluded from Windows Update by policy' 'ExcludeWUDriversInQualityUpdate = 1' 'Driver updates must come from OEM/vendor tools.' }
    if ($W.UpdatePolicy.WSUSServer) { Add-Finding 'info' 'Windows' 'PC is pointed at a WSUS server' $W.UpdatePolicy.WSUSServer 'Leftover from a company image? It can block normal updates.' }
    if ($W.UpdatePolicy.WUServiceStartType -eq 'Disabled') { Add-Finding 'high' 'Windows' 'Windows Update service is disabled' 'wuauserv start type: Disabled' 'Set the service back to Manual.' }
}

$S = $Audit.System
if ($S -and $S.BIOS.AgeDays -gt 730) {
    Add-Finding 'low' 'Firmware' "BIOS is $([math]::Round($S.BIOS.AgeDays/365,1)) years old ($($S.BIOS.Version), $($S.BIOS.ReleaseDate))" 'Older firmware is a common cause of sleep, USB, storage and stability issues; also carries CPU microcode/security fixes.' "Check $($S.Vendor) support for a newer BIOS for $($S.FriendlyModel). Never use a BIOS from a different model."
}

if ($Audit.Devices) {
    $prob = @($Audit.Devices | Where-Object { $_.Flags -contains 'Problem' -and $_.Present })
    foreach ($d in $prob) { Add-Finding 'high' 'Devices' "Device problem: $($d.Name)" $d.Problem 'See device row for driver links. Code 28 = install driver; 10/43 = update/reinstall driver or check hardware.' @("device|$($d.InstanceId)|$($d.ErrorCode)") }
    $nodrv = @($Audit.Devices | Where-Object { $_.Flags -contains 'NoDriver' -and $_.Flags -notcontains 'Problem' })
    if ($nodrv.Count) { Add-Finding 'medium' 'Devices' "$($nodrv.Count) hardware device(s) without a driver" (($nodrv | Select-Object -First 6 | ForEach-Object { $_.Name }) -join '; ') 'Look up by hardware ID (MS Catalog links in the device table).' @($nodrv | ForEach-Object { "device|$($_.InstanceId)|nodriver" }) }
    $gen = @($Audit.Devices | Where-Object { $_.Flags -contains 'GenericDriver' })
    if ($gen.Count) { Add-Finding 'medium' 'Drivers' "$($gen.Count) device(s) on generic Microsoft drivers" (($gen | ForEach-Object { $_.Name }) -join '; ') 'A vendor driver usually works better (graphics, audio, network, chipset).' }
    $old = @($Audit.Devices | Where-Object { $_.Flags -contains 'OldDriver' -and $_.Present })
    if ($old.Count) { Add-Finding 'low' 'Drivers' "$($old.Count) driver(s) older than $DriverAgeYears years" (($old | Sort-Object AgeYears -Descending | Select-Object -First 8 | ForEach-Object { "$($_.Name) ($($_.Date))" }) -join '; ') 'Check for newer versions - filter the device table by "OldDriver".' }
    $uns = @($Audit.Devices | Where-Object { $_.Flags -contains 'Unsigned' })
    if ($uns.Count) { Add-Finding 'medium' 'Drivers' "$($uns.Count) unsigned driver(s)" (($uns | ForEach-Object { $_.Name }) -join '; ') 'Unsigned drivers can be unstable or blocked; replace with signed versions.' }
}

if ($Audit.Hardware) {
    foreach ($d in @($Audit.Hardware.Disks)) {
        if ($d.Health -and $d.Health -ne 'Healthy') { Add-Finding 'high' 'Storage' "Disk health: $($d.Name) reports $($d.Health)" $d.OperationalStatus 'Back up data now and check SMART with the drive maker''s tool.' }
        if ($d.Reliability -and $d.Reliability.WearPercent -ge 80) { Add-Finding 'medium' 'Storage' "SSD wear $($d.Reliability.WearPercent)%: $($d.Name)" '' 'Plan replacement.' }
    }
    foreach ($v in @($Audit.Hardware.Volumes)) {
        if ($v.Drive -eq $env:SystemDrive -and $v.FreeGB -lt 20) { Add-Finding 'medium' 'Storage' "Low space on $($v.Drive) ($($v.FreeGB) GB free)" 'Updates (especially feature updates) need 20+ GB free.' 'Free up space / run Disk Cleanup.' }
    }
}

if ($Audit.WindowsUpdate) {
    $unres = @($Audit.WindowsUpdate.Failures | Where-Object { $_.Resolution -in @('Unresolved','Still pending') })
    $uniq = @($unres | Group-Object { if ($_.KB) { $_.KB } else { $_.Title } } | ForEach-Object { $_.Group[0] })
    if ($uniq.Count) {
        Add-Finding 'medium' 'Windows Update' "$($uniq.Count) failed update(s) with no later fix found" (($uniq | Select-Object -First 6 | ForEach-Object { "$($_.Title) [$($_.HResult)]" }) -join '; ') 'See Windows Update section for error meanings.' @($uniq | ForEach-Object { $_.Key }) (@($unres | ForEach-Object { $_.Date } | Sort-Object) | Select-Object -Last 1)
    }
    $rep = @($Audit.WindowsUpdate.Failures | Where-Object { $_.FailCount -ge 3 } | Group-Object { if ($_.KB) { $_.KB } else { $_.Title } })
    foreach ($r in $rep) { Add-Finding 'medium' 'Windows Update' "Update failed $($r.Group[0].FailCount) times: $($r.Name)" ($r.Group[0].ErrorMeaning) 'Repeated failure points to cache/component-store damage: reset update components, then DISM /RestoreHealth.' @($r.Group[0].Key) (@($r.Group | ForEach-Object { $_.Date } | Sort-Object) | Select-Object -Last 1) }
    if ($Audit.WindowsUpdate.Pending) {
        $drv = @($Audit.WindowsUpdate.Pending | Where-Object { $_.Type -eq 'Driver' })
        $sw  = @($Audit.WindowsUpdate.Pending | Where-Object { $_.Type -ne 'Driver' })
        if ($sw.Count)  { Add-Finding 'medium' 'Windows Update' "$($sw.Count) Windows update(s) waiting to install" (($sw | ForEach-Object { $_.Title }) -join '; ') 'Install via Settings > Windows Update.' }
        if ($drv.Count) { Add-Finding 'low' 'Windows Update' "$($drv.Count) driver update(s) offered by Windows Update" (($drv | ForEach-Object { $_.Title }) -join '; ') 'Settings > Windows Update > Advanced > Optional updates. Prefer OEM versions for audio/graphics on laptops.' }
    }
}

if ($Audit.Crashes -and $Audit.Crashes.BugChecks.Count) {
    $recent = @($Audit.Crashes.BugChecks | Where-Object { $_.Date -and ([datetime]$_.Date) -gt (Get-Date).AddDays(-90) })
    if ($recent.Count) {
        $names = ($recent | Group-Object { if ($_.Name) { $_.Name } else { $_.Code } } | Sort-Object Count -Descending | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join '; '
        Add-Finding 'high' 'Stability' "$($recent.Count) blue screen(s) in the last 90 days" $names 'Open the minidumps with WinDbg (!analyze -v) or BlueScreenView to find the driver involved.' @('crashes') (@($recent | ForEach-Object { $_.Date } | Sort-Object) | Select-Object -Last 1)
    }
}
if ($Audit.EventIssues) {
    foreach ($e in @($Audit.EventIssues | Where-Object { $_.Severity -eq 'high' -and $_.Category -ne 'Crash / power' })) {
        $rel = if ($e.RelatedDevices.Count) { " Related: $($e.RelatedDevices -join ', ')." } else { '' }
        $relog = if ($e.Logged) { " Windows logged it $($e.Logged) times; only $($e.Count) were separate occurrences." } else { '' }
        Add-Finding 'high' $e.Category "$($e.Provider) event $($e.Id) x$($e.Count) (last $($e.Last -replace 'T', ' '))" ($e.Hint + $rel + $relog) 'See Event log section for details.' @($e.Key) $e.Last
    }
    $kp = @($Audit.EventIssues | Where-Object { $_.Provider -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -eq 41 })
    if ($kp.Count -and $kp[0].Count -ge 2) { Add-Finding 'medium' 'Stability' "$($kp[0].Count) unexpected restarts in $EventDays days" $kp[0].Hint 'Correlate with BSODs; if none, suspect power/PSU or hard hangs (GPU/storage).' @($kp[0].Key) $kp[0].Last }
}
if ($Audit.DriverInstallFailures -and $Audit.DriverInstallFailures.Count) {
    $recentDi = @($Audit.DriverInstallFailures | Select-Object -First 5)
    Add-Finding 'medium' 'Drivers' "$($Audit.DriverInstallFailures.Count) failed driver install operation(s) in setupapi log" (($recentDi | ForEach-Object { "$($_.Date) $($_.Operation) [$($_.Status)]" }) -join '; ') 'See Driver install failures section.' @('setupapi') $Audit.DriverInstallFailures[0].Date
}
if ($Audit.ServicingLogs -and $Audit.ServicingLogs.RollbackFolderPresent) {
    Add-Finding 'high' 'Windows Update' 'A feature upgrade was rolled back' 'C:\$WINDOWS.~BT\Sources\Rollback exists.' 'Run Microsoft SetupDiag to get the exact cause (often a driver - error 0xC1900101).' @('rollback')
}

if ($Audit.Online) {
    $B = $Audit.Online.Board
    if ($B -and $B.Latest -and $B.Status -match 'newer') {
        $sev = 'low'
        try { if ($B.Latest.Date -and $S.BIOS.ReleaseDate -and (([datetime]$B.Latest.Date - [datetime]$S.BIOS.ReleaseDate).TotalDays -gt 180)) { $sev = 'medium' } } catch {}
        Add-Finding $sev 'Firmware' "BIOS update available: $($B.Installed) -> $($B.Latest.Version) ($($B.Latest.Date))" "$($B.Status). $($B.Note)" "Download from $($B.Vendor) for $($B.MatchedProduct): see the Updates tab. Flash only files for this exact board."
        # replace the generic 'BIOS is old' finding
        $old = @($findings | Where-Object { $_.Area -eq 'Firmware' -and $_.Title -like 'BIOS is*' })
        foreach ($x in $old) { [void]$findings.Remove($x) }
    }
    $catNewer = @($Audit.Devices | Where-Object { $_.Catalog -and $_.Catalog.Status -in @('Newer version available', 'Vendor driver available') })
    if ($catNewer.Count) {
        Add-Finding 'low' 'Drivers' "$($catNewer.Count) device(s) have newer drivers in the Microsoft Update Catalog" (($catNewer | ForEach-Object { if ($_.Catalog.FamilyLatest) { "$($_.Name): $($_.Version) -> $($_.Catalog.FamilyLatest.Version)" } else { "$($_.Name): vendor driver available" } }) -join '; ') 'See the Updates tab. Catalog drivers are Microsoft-signed; download the .cab and install via Device Manager > Update driver > Browse.'
    }
    $newer = @($Audit.Online.BoardDrivers | Where-Object { $_.Status -in @('Newer available', 'Probably newer (by date)', 'Generic Windows driver - vendor driver available') })
    if ($newer.Count) { Add-Finding 'low' 'Drivers' "$($newer.Count) newer driver(s) on the board maker's site" (($newer | ForEach-Object { "$($_.Name) $($_.Version)" }) -join '; ') 'See the Updates tab for installed vs available versions.' }
    foreach ($g in @($Audit.Online.GPUs | Where-Object { $_.Status -eq 'Newer available' -and $_.Latest })) {
        $sev = 'low'; try { if ($g.InstalledDate -and (([datetime]$g.Latest.Date - [datetime]$g.InstalledDate).TotalDays -gt 180)) { $sev = 'medium' } } catch {}
        Add-Finding $sev 'Drivers' "Graphics driver update: $($g.Name) $($g.VendorVersion) -> $($g.Latest.Version) ($($g.Latest.Date))" $g.Latest.Name 'Download from the Updates tab.'
    }
}

if ($Audit.History -and $Audit.History.PreviousScan) {
    $ch = @($Audit.History.Changes); $by = @($ch | Where-Object { $_.ByPcAudit })
    if ($ch.Count) { Add-Finding 'info' 'Change history' "$($ch.Count) change(s) since the last scan on $(Format-Date $Audit.History.PreviousScan.Date)$(if ($by.Count) { ", $($by.Count) of them through or recommended by PC Audit" })" (($ch | Select-Object -First 5 | ForEach-Object { "$($_.Kind): $($_.Item)$(if ($_.To) { ' -> ' + $_.To })" }) -join '; ') 'See the Change history tab.' }
}

# Dismissed items: one JSON object per line, latest line per key wins ({"Op":"dismiss"|"restore","Key","At","Title"})
$disFile = Join-Path (Split-Path $OutputDir -Parent) ("{0}.dismissed.jsonl" -f $env:COMPUTERNAME)
$dis = [ordered]@{}
if (Test-Path -LiteralPath $disFile) {
    foreach ($ln in @(Get-Content -LiteralPath $disFile -Encoding UTF8)) {
        try { $o = $ln | ConvertFrom-Json } catch { continue }
        if (-not $o -or -not $o.Key) { continue }
        if ($o.Op -eq 'window') { $winDays = 0; [void][int]::TryParse([string]$o.Days, [ref]$winDays); $Audit.IgnoreOlderThanDays = $winDays; continue }
        if ($o.Op -eq 'restore') { $dis.Remove([string]$o.Key) } else { $dis[[string]$o.Key] = [pscustomobject]@{ Key = [string]$o.Key; At = (Format-Time $o.At); Title = [string]$o.Title } }
    }
}
if (-not $Audit.Contains('IgnoreOlderThanDays')) { $Audit.IgnoreOlderThanDays = 0 }
$Audit.Dismissals = @($dis.Values)
$Audit.DismissalsFile = $disFile

$sevOrder = @{ high = 0; medium = 1; low = 2; info = 3 }
$Audit.Findings = @($findings | Sort-Object @{e={ $sevOrder[$_.Severity] }})
$Audit.CollectionNotes = $script:CollectionNotes.ToArray()
$Audit.Meta.Finished = Format-Time (Get-Date)
$Audit.Meta.DurationSec = [int]((Get-Date) - $Started).TotalSeconds

# ---------------------------------------------------------------------------
# 14. Write output
# ---------------------------------------------------------------------------
Write-Step 'Writing report'
$json = $Audit | ConvertTo-Json -Depth 10 -Compress
$jsonPath = Join-Path $OutputDir 'audit.json'
[System.IO.File]::WriteAllText($jsonPath, $json, (New-Object System.Text.UTF8Encoding($false)))

$templatePath = if ($TemplatePath) { $TemplatePath } elseif ($PSScriptRoot) { Join-Path $PSScriptRoot 'report-template.html' } else { Join-Path (Get-Location) 'report-template.html' }
$reportPath = Join-Path $OutputDir ("PCAudit_{0}.html" -f $env:COMPUTERNAME)
if (Test-Path $templatePath) {
    $template = [System.IO.File]::ReadAllText($templatePath)
    $safeJson = $json -replace '</', '<\/'
    $html = $template.Replace('/*__AUDIT_DATA__*/null', $safeJson)
    [System.IO.File]::WriteAllText($reportPath, $html, (New-Object System.Text.UTF8Encoding($false)))
    Write-Host ''
    Write-Host "Report: $reportPath" -ForegroundColor Green
    if (-not $NoOpen) { Start-Process $reportPath }
} else {
    Write-Host "report-template.html not found next to the script; only audit.json was written." -ForegroundColor Yellow
}
Write-Host "Data:   $jsonPath" -ForegroundColor Green
Write-Host ("Findings: {0} high, {1} medium, {2} low" -f @($Audit.Findings | Where-Object Severity -eq 'high').Count,
    @($Audit.Findings | Where-Object Severity -eq 'medium').Count, @($Audit.Findings | Where-Object Severity -eq 'low').Count)
