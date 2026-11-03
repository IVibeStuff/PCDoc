<#
.SYNOPSIS
    PCDoc - download and install helper. Runs one action from a scan's audit.json.

.DESCRIPTION
    Stages (the app asks the user before each stage that changes anything):
      Prepare  - download the file from the manufacturer / Microsoft, check its digital signature,
                 unpack it. Nothing is installed.
      Install  - driver packages (.inf): create a restore point, then install with Windows' pnputil.
      Launch   - installers (.exe): open the manufacturer's own setup program, so its own screens
                 do the installing.
    Files go to <Downloads>\PCDoc\<computer>\<date>\ and every step is recorded in
    <Downloads>\PCDoc\<computer>\downloads.log (one JSON object per line).

    Output lines for the app:  "PROGRESS <percent> <text>", then "R:<Key>=<Value>" lines and a final "RESULT <json>".
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$AuditJson,
    [Parameter(Mandatory = $true)][string]$ActionId,
    [ValidateSet('Prepare', 'Install', 'Launch')][string]$Stage = 'Prepare',
    [string]$DownloadRoot
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

# Only these hosts may be downloaded from (HTTPS only)
$AllowedHosts = @(
    'catalog.s.download.windowsupdate.com', 'download.windowsupdate.com', 'catalog.sf.dl.delivery.mp.microsoft.com',
    'us.download.nvidia.com', 'international.download.nvidia.com', 'download.nvidia.com',
    'drivers.amd.com', 'download.amd.com',
    'download.asrock.com', 'download.msi.com', 'download-2.msi.com', 'dlcdnets.asus.com', 'dlcdn.asus.com',
    'download.gigabyte.com', 'downloadmirror.intel.com', 'downloadcenter.intel.com'
)

function Out-Progress([double]$pct, [string]$text) { Write-Host ("PROGRESS {0} {1}" -f [int][math]::Round($pct), $text) }
function Join-Ordered($a, $b) { $r = [ordered]@{}; foreach ($k in $a.Keys) { $r[$k] = $a[$k] }; foreach ($k in $b.Keys) { $r[$k] = $b[$k] }; return $r }
function Out-Result($obj) {
    # Simple "R:Key=Value" lines for the app (one per field, no JSON parsing needed), then the full JSON
    foreach ($k in @('Stage', 'Ok', 'Next', 'Note', 'Error', 'Title', 'Signer', 'SignatureStatus', 'Folder', 'File', 'Outcome', 'ExitCode', 'RestorePoint', 'FromVersion', 'ToVersion', 'Kind')) {
        if ($obj.Contains($k) -and $null -ne $obj[$k] -and "$($obj[$k])" -ne '') { Write-Host ("R:{0}={1}" -f $k, (("$($obj[$k])") -replace "`r?`n", ' | ')) }
    }
    Write-Host ("RESULT " + ($obj | ConvertTo-Json -Depth 6 -Compress))
}

function Get-UserDownloadsFolder {
    # The signed-in user's Downloads folder. If the app was elevated with a different admin account,
    # use the desktop user's folder instead of the admin's.
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
                if ($prof -and $prof.LocalPath) {
                    $d = Join-Path $prof.LocalPath 'Downloads'
                    if (Test-Path $d) { return $d }
                }
            }
        }
    } catch {}
    return $mine
}

# PCDoc was called "PC Audit" up to 0.4.4. Its folders are renamed on first use so history, downloads and
# dismissals carry over. If a rename isn't possible (a file is open), the old folder keeps being used.
function Get-RenamedFolder([string]$Parent, [string]$NewName, [string]$OldName) {
    $new = Join-Path $Parent $NewName; $old = Join-Path $Parent $OldName
    if (-not (Test-Path -LiteralPath $new) -and (Test-Path -LiteralPath $old)) {
        try { Move-Item -LiteralPath $old -Destination $new -ErrorAction Stop } catch { return $old }
    }
    return $new
}

function Write-DownloadLog([string]$LogPath, $Entry) {
    $Entry | Add-Member -NotePropertyName Time -NotePropertyValue ((Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')) -Force
    $Entry | Add-Member -NotePropertyName Computer -NotePropertyValue $env:COMPUTERNAME -Force
    Add-Content -LiteralPath $LogPath -Value ($Entry | ConvertTo-Json -Depth 5 -Compress) -Encoding UTF8
}

function Test-Signature([string]$Path, [string]$ExpectedSigner) {
    $r = [ordered]@{ Status = 'NotSigned'; Signer = $null; Matches = $false }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path
        $r.Status = [string]$sig.Status
        if ($sig.SignerCertificate) {
            $cn = [regex]::Match($sig.SignerCertificate.Subject, 'CN=("[^"]+"|[^,]+)').Groups[1].Value.Trim('"')
            $o = [regex]::Match($sig.SignerCertificate.Subject, '\bO=("[^"]+"|[^,]+)').Groups[1].Value.Trim('"')
            $r.Signer = if ($o) { $o } else { $cn }
            $r.Matches = ($r.Status -eq 'Valid') -and (-not $ExpectedSigner -or $sig.SignerCertificate.Subject -match [regex]::Escape($ExpectedSigner))
        }
    } catch { $r.Status = 'Error: ' + $_.Exception.Message }
    return [pscustomobject]$r
}

function Save-Url([string]$Url, [string]$Dest, [string]$Referer) {
    $req = [Net.HttpWebRequest]::Create($Url)
    $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0'
    if ($Referer) { $req.Referer = $Referer }
    $req.AllowAutoRedirect = $true; $req.Timeout = 60000; $req.ReadWriteTimeout = 120000
    $resp = $req.GetResponse()
    $final = $resp.ResponseUri
    if ($final.Scheme -ne 'https' -or ($AllowedHosts -notcontains $final.Host.ToLower())) { $resp.Close(); throw "Download was redirected to an unexpected address ($($final.Host)). Stopped for safety." }
    $total = [int64]$resp.ContentLength
    $in = $resp.GetResponseStream()
    $out = [IO.File]::Create($Dest)
    try {
        $buf = New-Object byte[] (1MB); $done = [int64]0; $lastPct = -1; $sw = [Diagnostics.Stopwatch]::StartNew()
        while (($n = $in.Read($buf, 0, $buf.Length)) -gt 0) {
            $out.Write($buf, 0, $n); $done += $n
            if ($total -gt 0) {
                $pct = [int](100 * $done / $total)
                if ($pct -ne $lastPct -and ($pct % 2 -eq 0)) {
                    $mbps = if ($sw.Elapsed.TotalSeconds -gt 0) { ($done / 1MB) / $sw.Elapsed.TotalSeconds } else { 0 }
                    Out-Progress ($pct * 0.9) ("Downloading {0:N1} of {1:N1} MB ({2:N1} MB/s)" -f ($done / 1MB), ($total / 1MB), $mbps); $lastPct = $pct
                }
            } elseif ($done % (8MB) -lt $n) { Out-Progress 45 ("Downloading {0:N1} MB" -f ($done / 1MB)) }
        }
    } finally { $out.Close(); $in.Close(); $resp.Close() }
    return $done
}

# ---------------------------------------------------------------------------
try {
    $audit = Get-Content -LiteralPath $AuditJson -Raw -Encoding UTF8 | ConvertFrom-Json
    $action = @($audit.Actions) | Where-Object { $_.Id -eq $ActionId } | Select-Object -First 1
    if (-not $action) { throw "Action $ActionId was not found in this scan." }

    if (-not $DownloadRoot) { $DownloadRoot = Get-RenamedFolder (Get-UserDownloadsFolder) 'PCDoc' 'PC Audit' }
    $pcRoot = Join-Path $DownloadRoot $env:COMPUTERNAME
    $dayDir = Join-Path $pcRoot (Get-Date -Format 'yyyy-MM-dd')
    New-Item -ItemType Directory -Force -Path $dayDir | Out-Null
    $log = Join-Path $pcRoot 'downloads.log'
    $safeName = ($action.Title -replace '[^\w\.\-\(\) ]', '_' -replace '\s+', ' ').Trim()
    if ($safeName.Length -gt 80) { $safeName = $safeName.Substring(0, 80) }
    $workDir = Join-Path $dayDir $safeName

    $base = [ordered]@{ ActionId = $action.Id; Kind = $action.Kind; Title = $action.Title; Device = $action.Device; InstanceIds = @($action.InstanceIds)
                        FromVersion = $action.FromVersion; ToVersion = $action.ToVersion; Source = $action.Source; Url = $action.Url }

    switch ($Stage) {
        'Prepare' {
            $uri = [uri]$action.Url
            if ($uri.Scheme -ne 'https' -or ($AllowedHosts -notcontains $uri.Host.ToLower())) { throw "Downloads from $($uri.Host) are not on the allowed list." }
            New-Item -ItemType Directory -Force -Path $workDir | Out-Null
            $fileName = [IO.Path]::GetFileName([uri]::UnescapeDataString($uri.AbsolutePath))
            if (-not $fileName) { $fileName = 'download.bin' }
            $file = Join-Path $workDir $fileName
            Out-Progress 1 "Connecting to $($uri.Host)"
            $bytes = Save-Url $action.Url $file $action.Referer
            Out-Progress 91 'Checking the digital signature'
            $sha = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash

            $ext = [IO.Path]::GetExtension($file).ToLower()
            $sig = $null; $extracted = $null; $infs = @(); $launch = $null; $next = 'manual'; $note = $null
            if ($ext -in @('.cab', '.exe', '.msi')) { $sig = Test-Signature $file $action.ExpectedSigner }

            if ($ext -eq '.cab') {
                Out-Progress 94 'Unpacking the driver package'
                $extracted = Join-Path $workDir 'extracted'; New-Item -ItemType Directory -Force -Path $extracted | Out-Null
                & "$env:SystemRoot\System32\expand.exe" -F:* $file $extracted | Out-Null
                $infs = @(Get-ChildItem -LiteralPath $extracted -Filter *.inf -Recurse -ErrorAction SilentlyContinue | ForEach-Object FullName)
                # Driver packages are signed through their catalog (.cat) file, issued by Microsoft
                $catOk = $false
                foreach ($cat in @(Get-ChildItem -LiteralPath $extracted -Filter *.cat -Recurse -ErrorAction SilentlyContinue)) {
                    $cs = Test-Signature $cat.FullName 'Microsoft'
                    if ($cs.Matches) { $catOk = $true; if (-not $sig -or -not $sig.Matches) { $sig = $cs } }
                }
                if (-not $infs.Count) { $next = 'manual'; $note = 'No driver (.inf) files were found in the package.' }
                elseif (-not ($catOk -or ($sig -and $sig.Matches))) { $next = 'blocked'; $note = 'The driver package is not signed by Microsoft. It was not installed.' }
                else { $next = 'install' }
            }
            elseif ($ext -eq '.zip') {
                Out-Progress 94 'Unpacking'
                $extracted = Join-Path $workDir 'extracted'
                Expand-Archive -LiteralPath $file -DestinationPath $extracted -Force
                $infs = @(Get-ChildItem -LiteralPath $extracted -Filter *.inf -Recurse -ErrorAction SilentlyContinue | ForEach-Object FullName)
                $setup = Get-ChildItem -LiteralPath $extracted -Recurse -Include *.exe -ErrorAction SilentlyContinue |
                         Sort-Object @{ e = { if ($_.Name -match '(?i)^(setup|install|asussetup|autorun)') { 0 } elseif ($_.Name -match '(?i)setup|install') { 1 } else { 2 } } },
                                     @{ e = { ($_.FullName.Split('\')).Count } } | Select-Object -First 1
                if ($action.Kind -eq 'bios') { $next = 'manual'; $note = 'BIOS files are flashed from the BIOS itself (Instant Flash / Q-Flash / EZ Flash / M-Flash), not from Windows.' }
                elseif ($setup) {
                    $launch = $setup.FullName; $sig = Test-Signature $launch $action.ExpectedSigner
                    if ($sig.Status -eq 'Valid') { $next = 'launch' }
                    else { $next = 'manual'; $note = "The setup program ($($setup.Name)) has no valid digital signature, so PCDoc will not open it. Open the folder to inspect it." }
                }
                elseif ($infs.Count) { $next = 'install' }
                else { $next = 'manual'; $note = 'No installer or driver files were found. Open the folder to look.' }
            }
            elseif ($ext -in @('.exe', '.msi')) {
                $launch = $file
                if ($action.ExpectedSigner -and -not $sig.Matches) { $next = 'blocked'; $note = "The installer is not signed by $($action.ExpectedSigner). It was not opened." }
                elseif ($sig.Status -ne 'Valid') { $next = 'blocked'; $note = 'The installer has no valid digital signature. It was not opened.' }
                else { $next = 'launch' }
            }
            if ($action.Kind -eq 'bios') { $next = 'manual'; if (-not $note) { $note = 'BIOS files are flashed from the BIOS itself, not from Windows.' } }

            $res = Join-Ordered $base ([ordered]@{ Stage = 'Prepare'; Ok = $true; File = $file; Folder = $workDir; Bytes = $bytes; Sha256 = $sha
                Signer = $(if ($sig) { $sig.Signer }); SignatureStatus = $(if ($sig) { $sig.Status } else { 'Not applicable (archive)' })
                SignatureOk = $(if ($sig) { [bool]$sig.Matches } else { $null }); Extracted = $extracted; InfFiles = $infs; LaunchTarget = $launch; Next = $next; Note = $note })
            Write-DownloadLog $log ([pscustomobject]$res)
            Out-Progress 100 'Ready'
            Out-Result $res
        }

        'Install' {
            $prep = Get-Content -LiteralPath $log -Encoding UTF8 | ForEach-Object { try { $_ | ConvertFrom-Json } catch {} } |
                    Where-Object { $_.ActionId -eq $ActionId -and $_.Stage -eq 'Prepare' -and $_.Next -eq 'install' -and $_.Computer -eq $env:COMPUTERNAME } | Select-Object -Last 1
            if (-not $prep) { throw 'Download this update first.' }
            $folder = if ($prep.Extracted) { $prep.Extracted } else { $prep.Folder }
            Out-Progress 10 'Creating a System Restore point'
            $rp = 'Created'
            $rpName = "PCDoc: before $($action.Title)"; if ($rpName.Length -gt 60) { $rpName = $rpName.Substring(0, 60) }
            try { Checkpoint-Computer -Description $rpName -RestorePointType MODIFY_SETTINGS -ErrorAction Stop }
            catch { $rp = 'Skipped: ' + $_.Exception.Message }
            Out-Progress 40 'Installing the driver with Windows (pnputil)'
            $pnp = & "$env:SystemRoot\System32\pnputil.exe" /add-driver (Join-Path $folder '*.inf') /subdirs /install 2>&1 | Out-String
            $code = $LASTEXITCODE
            $meaning = switch ($code) { 0 { 'Installed' } 3010 { 'Installed - restart needed to finish' } 259 { 'Added to Windows, but no device took it (the device already has an equal or better driver)' } default { "pnputil reported code $code" } }
            Out-Progress 90 'Checking the device driver version'
            $now = @()
            foreach ($id in @($action.InstanceIds)) {
                $d = Get-CimInstance Win32_PnPSignedDriver -Filter ("DeviceID='{0}'" -f ($id -replace '\\', '\\')) -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($d) { $now += [pscustomobject]@{ InstanceId = $id; Device = $d.DeviceName; Version = $d.DriverVersion } }
            }
            $res = Join-Ordered $base ([ordered]@{ Stage = 'Install'; Ok = ($code -in @(0, 3010)); ExitCode = $code; Outcome = $meaning; RestorePoint = $rp
                                       NowInstalled = $now; Output = (($pnp -split "`r?`n" | Where-Object { $_.Trim() }) | Select-Object -Last 12) -join "`n" })
            Write-DownloadLog $log ([pscustomobject]$res)
            Out-Progress 100 $meaning
            Out-Result $res
        }

        'Launch' {
            $prep = Get-Content -LiteralPath $log -Encoding UTF8 | ForEach-Object { try { $_ | ConvertFrom-Json } catch {} } |
                    Where-Object { $_.ActionId -eq $ActionId -and $_.Stage -eq 'Prepare' -and $_.Next -eq 'launch' -and $_.Computer -eq $env:COMPUTERNAME } | Select-Object -Last 1
            if (-not $prep) { throw 'Download this update first.' }
            $sig = Test-Signature $prep.LaunchTarget $action.ExpectedSigner
            if ($action.ExpectedSigner -and -not $sig.Matches) { throw "The installer's signature no longer checks out ($($sig.Status)). It was not opened." }
            Out-Progress 50 'Opening the manufacturer''s installer'
            Start-Process -FilePath $prep.LaunchTarget -WorkingDirectory (Split-Path $prep.LaunchTarget) | Out-Null
            $res = Join-Ordered $base ([ordered]@{ Stage = 'Launch'; Ok = $true; Outcome = 'Installer opened'; LaunchTarget = $prep.LaunchTarget; Signer = $sig.Signer })
            Write-DownloadLog $log ([pscustomobject]$res)
            Out-Progress 100 'Installer opened'
            Out-Result $res
        }
    }
}
catch {
    $msg = $_.Exception.Message
    try { if ($log) { Write-DownloadLog $log ([pscustomobject]([ordered]@{ ActionId = $ActionId; Stage = $Stage; Ok = $false; Error = $msg })) } } catch {}
    Out-Result ([ordered]@{ ActionId = $ActionId; Stage = $Stage; Ok = $false; Error = $msg })
}
