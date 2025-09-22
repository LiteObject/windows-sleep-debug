# SleepDebug.ps1
# Collects power debugging info + Event Viewer logs to troubleshoot sleep/resume issues

param(
    [Parameter(Mandatory=$false)]
    [string]$OutDir
)

# 0. Require Administrator
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "This script requires Administrator privileges. Please right-click PowerShell and 'Run as Administrator'."
    exit 1
}

# 0b. Resolve output directory and timestamp
if (-not $OutDir -or $OutDir.Trim() -eq "") {
    $OutDir = Join-Path $env:USERPROFILE 'Desktop'
}
try {
    if (-not (Test-Path -LiteralPath $OutDir)) {
        New-Item -Path $OutDir -ItemType Directory -Force | Out-Null
    }
} catch {
    Write-Warning "Failed to create or access output directory: '$OutDir'. Error: $($_.Exception.Message)"
    exit 1
}
Write-Output "Output directory: $OutDir"

$timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'

Write-Output "=== 1. Last Wake Event ==="
powercfg /lastwake
Write-Output "`n"

Write-Output "=== 2. Devices Allowed to Wake PC ==="
powercfg /devicequery wake_armed
Write-Output "`n"

Write-Output "=== 2b. Devices Programmable to Wake PC ==="
powercfg /devicequery wake_programmable
Write-Output "`n"

Write-Output "=== 3. Power Requests (blocking sleep) ==="
powercfg /requests
Write-Output "`n"

Write-Output "=== 4. Available Sleep States ==="
powercfg /a
Write-Output "`n"

Write-Output "=== 5. Generating Sleep Study Report ==="
$SleepReport = Join-Path $OutDir ("sleepstudy-report-" + $timestamp + ".html")
powercfg /sleepstudy
Copy-Item "C:\Windows\System32\sleepstudy-report.html" $SleepReport -Force
Write-Output "Sleep Study saved to: $SleepReport"
Write-Output "`n"

Write-Output "=== 6. Generating Energy Report (60s wait) ==="
$EnergyReport = Join-Path $OutDir ("energy-report-" + $timestamp + ".html")
powercfg /energy /output $EnergyReport /duration 60
Write-Output "Energy Report saved to: $EnergyReport"
Write-Output "`n"

Write-Output "=== 7. Wake Timers ==="
powercfg /waketimers
Write-Output "`n"

Write-Output "=== 8. Display/GPU and Monitor Info ==="
try {
    Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion, DriverDate, PNPDeviceID, Status | Format-Table -AutoSize
} catch { Write-Warning "Could not query Win32_VideoController: $($_.Exception.Message)" }
try {
    Get-PnpDevice -Class Display, Monitor | Select-Object Class, FriendlyName, Status, InstanceId | Format-Table -AutoSize
} catch { Write-Warning "Could not query PnP devices (Display/Monitor): $($_.Exception.Message)" }
Write-Output "`n"

Write-Output "=== 9. USB & Sleep Settings (powercfg query) ==="
Write-Output "- USB Selective Suspend"
powercfg /query SCHEME_CURRENT SUB_USB USBSELECTIVESUSPEND
Write-Output ""
Write-Output "- USB 3 Link Power Management (if present)"
try { powercfg /query SCHEME_CURRENT SUB_USB USB3LINKPOWERMANAGEMENT } catch { Write-Output "Setting not found on this system." }
Write-Output ""
Write-Output "- Hybrid Sleep"
powercfg /query SCHEME_CURRENT SUB_SLEEP HYBRIDSLEEP
Write-Output ""
Write-Output "- Allow wake timers (AC)"
powercfg /query SCHEME_CURRENT SUB_SLEEP ALLOWWAKE
Write-Output "`n"

Write-Output "=== 10. Fast Startup Status ==="
try {
    $fastStartup = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name HiberbootEnabled -ErrorAction Stop).HiberbootEnabled
    if ($fastStartup -eq 1) {
        Write-Output "Fast Startup: ENABLED (HiberbootEnabled=1)"
    } elseif ($fastStartup -eq 0) {
        Write-Output "Fast Startup: DISABLED (HiberbootEnabled=0)"
    } else {
        Write-Output "Fast Startup: Unknown value ($fastStartup)"
    }
} catch { Write-Output "Fast Startup: Not found (likely disabled)" }
Write-Output "`n"

Write-Output "=== 11. Enhanced Event Viewer Logs (last 7 days) ==="
$startTime = (Get-Date).AddDays(-7)

$systemIds = 41, 1, 42, 107, 6008, 10110, 10111
$systemLogs = Get-WinEvent -FilterHashtable @{ LogName = 'System'; StartTime = $startTime } -ErrorAction SilentlyContinue |
    Where-Object { ($_.Id -in $systemIds) -or ($_.ProviderName -match 'Display|Graphics|Monitor|Power') }

$appLogs = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $startTime } -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'Display|Graphics|dwm|Desktop Window Manager|AppModel-Runtime' }

$allLogs = @()
if ($systemLogs) { $allLogs += $systemLogs }
if ($appLogs) { $allLogs += $appLogs }

if ($allLogs.Count -gt 0) {
    $xmlPath = Join-Path $OutDir ("SleepDebug-Events-" + $timestamp + ".xml")
    $txtPath = Join-Path $OutDir ("SleepDebug-Events-" + $timestamp + ".txt")
    $allLogs | Sort-Object TimeCreated -Descending | Select-Object -First 200 | Export-Clixml -Path $xmlPath -Force
    $allLogs | Sort-Object TimeCreated -Descending | Select-Object -First 200 |
        Format-Table TimeCreated, Id, ProviderName, Message -AutoSize | Out-File -FilePath $txtPath -Width 240 -Encoding UTF8
    Write-Output "Event logs exported to:"
    Write-Output "  - XML: $xmlPath"
    Write-Output "  - TXT: $txtPath"
} else {
    Write-Output "No relevant power/display events found in the last 7 days."
}
Write-Output "`n"

Write-Output "=== 12. BIOS/UEFI Wake Enable (device capabilities) ==="
try {
    Get-CimInstance -Namespace root/WMI -ClassName MSPower_DeviceWakeEnable | Select-Object InstanceName, Enable | Format-Table -AutoSize
} catch { Write-Warning "Could not query MSPower_DeviceWakeEnable: $($_.Exception.Message)" }
Write-Output "`n"

Write-Output "=== 13. Active Power Plan Details ==="
$activePlan = (powercfg /getactivescheme)
Write-Output $activePlan
Write-Output "- Display idle (AC)"
powercfg /query SCHEME_CURRENT SUB_VIDEO VIDEOIDLE
Write-Output "- Console lock display off timeout"
powercfg /query SCHEME_CURRENT SUB_VIDEO VIDEOCONLOCK
Write-Output "`n"

Write-Output "=== 14. Recommendations (do not change settings automatically) ==="
Write-Output "1) Consider disabling Fast Startup temporarily to test resume stability:"
Write-Output "   powercfg /h off"
Write-Output ""
Write-Output "2) Update GPU/display drivers from the OEM (NVIDIA/AMD/Intel) and motherboard chipset drivers."
Write-Output ""
Write-Output "3) If resume issues persist, test with Hybrid Sleep off (AC):"
Write-Output "   powercfg /setacvalueindex SCHEME_CURRENT SUB_SLEEP HYBRIDSLEEP 0"
Write-Output "   powercfg /setactive SCHEME_CURRENT"
Write-Output ""
Write-Output "4) Test with USB Selective Suspend disabled (AC):"
Write-Output "   powercfg /setacvalueindex SCHEME_CURRENT SUB_USB USBSELECTIVESUSPEND 0"
Write-Output "   powercfg /setactive SCHEME_CURRENT"
Write-Output ""
Write-Output "5) Check wake sources and disable unwanted device wake capability:"
Write-Output "   Device Manager > device Properties > Power Management > uncheck 'Allow this device to wake the computer'"
Write-Output ""
Write-Output "6) If Event 41 persists with Checkpoint ~16, suspect resume/graphics handoff. Try a different cable/port, BIOS update, and disable C-states/ERP only for testing."
Write-Output ""

Write-Output "=== Debug Info Collection Completed ==="
