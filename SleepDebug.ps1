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
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
    $OutDir = Join-Path $scriptRoot 'reports'
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

Write-Output "=== 0. System Information ==="
try {
    $computerSystem = Get-CimInstance Win32_ComputerSystem
    $bios = Get-CimInstance Win32_BIOS
    $os = Get-CimInstance Win32_OperatingSystem
    $processor = Get-CimInstance Win32_Processor | Select-Object -First 1
    $motherboard = Get-CimInstance Win32_BaseBoard
    
    Write-Output "Computer: $($computerSystem.Name)"
    Write-Output "Manufacturer: $($computerSystem.Manufacturer)"
    Write-Output "Model: $($computerSystem.Model)"
    Write-Output "System Type: $($computerSystem.SystemType)"
    Write-Output "Total Physical Memory: $([math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)) GB"
    Write-Output ""
    Write-Output "BIOS: $($bios.Manufacturer) $($bios.Name)"
    Write-Output "BIOS Version: $($bios.SMBIOSBIOSVersion)"
    Write-Output "BIOS Date: $($bios.ReleaseDate)"
    Write-Output ""
    Write-Output "OS: $($os.Caption) $($os.Version) Build $($os.BuildNumber)"
    Write-Output "OS Architecture: $($os.OSArchitecture)"
    Write-Output "Install Date: $($os.InstallDate)"
    Write-Output "Last Boot: $($os.LastBootUpTime)"
    Write-Output ""
    Write-Output "Processor: $($processor.Name)"
    Write-Output "Cores: $($processor.NumberOfCores) / Logical: $($processor.NumberOfLogicalProcessors)"
    Write-Output "Max Clock: $($processor.MaxClockSpeed) MHz"
    Write-Output ""
    Write-Output "Motherboard: $($motherboard.Manufacturer) $($motherboard.Product)"
    Write-Output "MB Version: $($motherboard.Version)"
    Write-Output "MB Serial: $($motherboard.SerialNumber)"
} catch { Write-Warning "Could not query system information: $($_.Exception.Message)" }
Write-Output "`n"

Write-Output "=== 0b. Power Capabilities and Features ==="
try {
    # System power capabilities
    Write-Output "System Power Capabilities:"
    $powerCaps = powercfg /a
    Write-Output $powerCaps
    Write-Output ""
    
    # Modern Standby support
    $connectedStandby = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name CsEnabled -ErrorAction SilentlyContinue
    if ($connectedStandby) {
        Write-Output "Connected Standby (Modern Standby): $($connectedStandby.CsEnabled -eq 1)"
    } else {
        Write-Output "Connected Standby (Modern Standby): Not supported/configured"
    }
    
    # Hibernate support
    $hibernateEnabled = (powercfg /a | Select-String "Hibernate").Count -gt 0
    Write-Output "Hibernate Available: $hibernateEnabled"
    
    # Platform role
    try {
        $platformRole = Get-CimInstance Win32_ComputerSystem | Select-Object -ExpandProperty PCSystemType
        $roleText = switch($platformRole) {
            0 { "Unspecified" }
            1 { "Desktop" }
            2 { "Mobile/Laptop" }
            3 { "Workstation" }
            4 { "Enterprise Server" }
            5 { "Small Office Server" }
            6 { "Appliance PC" }
            8 { "Tablet" }
            default { "Unknown ($platformRole)" }
        }
        Write-Output "System Role: $roleText"
    } catch { }
} catch { Write-Warning "Could not query power capabilities: $($_.Exception.Message)" }
Write-Output "`n"

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
powercfg /sleepstudy /output $SleepReport
if (Test-Path $SleepReport) {
    Write-Output "Sleep Study saved to: $SleepReport"
} else {
    Write-Warning "Sleep Study report could not be generated (may not be supported on this system)"
    Write-Output "Modern Standby/Connected Standby may not be available on this system."
}
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
    Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion, DriverDate, PNPDeviceID, Status, VideoMemoryType, AdapterRAM | Format-Table -AutoSize
} catch { Write-Warning "Could not query Win32_VideoController: $($_.Exception.Message)" }
try {
    Get-PnpDevice -Class Display, Monitor | Select-Object Class, FriendlyName, Status, InstanceId | Format-Table -AutoSize
} catch { Write-Warning "Could not query PnP devices (Display/Monitor): $($_.Exception.Message)" }
Write-Output "`n"

Write-Output "=== 8b. Memory and Storage Information ==="
try {
    # Memory modules
    Write-Output "Memory Modules:"
    $memory = Get-CimInstance Win32_PhysicalMemory
    foreach ($mem in $memory) {
        $size = [math]::Round($mem.Capacity / 1GB, 2)
        Write-Output "  $($mem.DeviceLocator): $size GB $($mem.MemoryType) @ $($mem.Speed) MHz"
        Write-Output "    Manufacturer: $($mem.Manufacturer), P/N: $($mem.PartNumber)"
    }
    Write-Output ""
    
    # Storage devices
    Write-Output "Storage Devices:"
    $disks = Get-CimInstance Win32_DiskDrive
    foreach ($disk in $disks) {
        $size = [math]::Round($disk.Size / 1GB, 2)
        Write-Output "  $($disk.Model): $size GB"
        Write-Output "    Interface: $($disk.InterfaceType), Status: $($disk.Status)"
    }
} catch { Write-Warning "Could not query memory/storage: $($_.Exception.Message)" }
Write-Output "`n"

Write-Output "=== 8b. Display Adapter Power Settings ==="
try {
    # Check for GPU-specific power settings
    $gpuDevices = Get-PnpDevice -Class Display | Where-Object {$_.Status -eq 'OK'}
    foreach ($gpu in $gpuDevices) {
        $deviceId = $gpu.InstanceId
        Write-Output "GPU: $($gpu.FriendlyName)"
        
        # Check if device can wake system
        $wakeEnabled = Get-CimInstance -ClassName MSPower_DeviceWakeEnable -Namespace root/wmi -ErrorAction SilentlyContinue | 
            Where-Object {$_.InstanceName -like "*$($deviceId.Replace('\','\\'))*"}
        if ($wakeEnabled) {
            Write-Output "  Wake Enabled: $($wakeEnabled.Enable)"
        }
        
        # Get power management capabilities
        try {
            $powerCaps = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction SilentlyContinue | 
                Where-Object {$_.PNPDeviceID -eq $deviceId} | 
                Select-Object -ExpandProperty PowerManagementCapabilities
            if ($powerCaps) {
                Write-Output "  Power Capabilities: $($powerCaps -join ', ')"
            }
        } catch { }
    }
} catch { Write-Warning "Could not query GPU power settings: $($_.Exception.Message)" }
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

Write-Output "=== 11b. Wake History Analysis ==="
try {
    # Get the last 10 wake events
    $wakeEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        ProviderName = 'Microsoft-Windows-Power-Troubleshooter'
        ID = 1
    } -MaxEvents 10 -ErrorAction SilentlyContinue
    
    if ($wakeEvents) {
        Write-Output "Recent Wake Events:"
        foreach ($wakeEvent in $wakeEvents) {
            $msg = $wakeEvent.Message
            if ($msg -match "Wake Source: (.+)") {
                Write-Output "  $(Get-Date $wakeEvent.TimeCreated -Format 'yyyy-MM-dd HH:mm:ss'): $($matches[1])"
            } else {
                Write-Output "  $(Get-Date $wakeEvent.TimeCreated -Format 'yyyy-MM-dd HH:mm:ss'): $($msg.Split([Environment]::NewLine)[0])"
            }
        }
    } else {
        Write-Output "No recent wake events found."
    }
} catch { Write-Warning "Could not analyze wake history: $($_.Exception.Message)" }
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

Write-Output "=== 15. Network Adapter Power Settings ==="
try {
    $netAdapters = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'}
    foreach ($adapter in $netAdapters) {
        Write-Output "Adapter: $($adapter.Name) [$($adapter.InterfaceDescription)]"
        Write-Output "  Driver: $($adapter.DriverInformation.DriverProvider) v$($adapter.DriverInformation.DriverVersion)"
        Write-Output "  Date: $($adapter.DriverInformation.DriverDate)"
        Write-Output "  Link Speed: $($adapter.LinkSpeed)"
        
        # Check WOL settings
        try {
            $wolSettings = Get-NetAdapterPowerManagement -Name $adapter.Name -ErrorAction SilentlyContinue
            if ($wolSettings) {
                Write-Output "  WOL Magic Packet: $($wolSettings.WakeOnMagicPacket)"
                Write-Output "  Wake on Pattern: $($wolSettings.WakeOnPattern)"
                Write-Output "  Device Sleep on Disconnect: $($wolSettings.DeviceSleepOnDisconnect)"
            }
        } catch { }
        
        # Check if device can wake system
        try {
            $deviceWake = powercfg /devicequery wake_armed | Where-Object {$_ -like "*$($adapter.InterfaceDescription)*"}
            if ($deviceWake) {
                Write-Output "  Can Wake System: YES"
            } else {
                Write-Output "  Can Wake System: NO"
            }
        } catch { }
        Write-Output ""
    }
} catch { Write-Warning "Could not query network adapter settings: $($_.Exception.Message)" }
Write-Output "`n"

Write-Output "=== 16. USB Controllers and Devices ==="
try {
    # USB Controllers
    Write-Output "USB Controllers:"
    $usbControllers = Get-CimInstance Win32_USBController
    foreach ($ctrl in $usbControllers) {
        Write-Output "  $($ctrl.Name)"
        Write-Output "    Status: $($ctrl.Status), PNP ID: $($ctrl.PNPDeviceID)"
    }
    Write-Output ""
    
    # USB Devices with wake capability
    Write-Output "USB Devices (Wake Capable):"
    $usbDevices = Get-PnpDevice -Class USB | Where-Object {$_.Status -eq 'OK'}
    $wakeArmed = powercfg /devicequery wake_armed
    foreach ($usb in $usbDevices) {
        $canWake = $wakeArmed | Where-Object {$_ -like "*$($usb.FriendlyName)*"}
        if ($canWake) {
            Write-Output "  $($usb.FriendlyName) - CAN WAKE"
        }
    }
} catch { Write-Warning "Could not query USB information: $($_.Exception.Message)" }
Write-Output "`n"

Write-Output "=== 16. Connected Display Information ==="
try {
    # Get monitor connection info
    $monitors = Get-CimInstance -Namespace root\wmi -ClassName WmiMonitorBasicDisplayParams -ErrorAction SilentlyContinue
    if ($monitors) {
        foreach ($mon in $monitors) {
            Write-Output "Monitor Instance: $($mon.InstanceName)"
            Write-Output "  Active: $($mon.Active)"
            Write-Output "  Display Type: $(switch($mon.VideoInputType){0{'Analog'};1{'Digital'};default{'Unknown'}})"
        }
    } else {
        Write-Output "No WMI monitor information available."
    }
    
    # Get additional display info
    $displayDevices = Get-CimInstance Win32_DesktopMonitor -ErrorAction SilentlyContinue
    if ($displayDevices) {
        Write-Output ""
        Write-Output "Desktop Monitor Information:"
        foreach ($display in $displayDevices) {
            Write-Output "  Name: $($display.Name)"
            Write-Output "  Status: $($display.Status)"
            Write-Output "  PNP Device ID: $($display.PNPDeviceID)"
        }
    }
} catch { Write-Warning "Could not query monitor information: $($_.Exception.Message)" }
Write-Output "`n"

Write-Output "=== 17. Chipset and Platform Information ==="
try {
    # Chipset information
    Write-Output "System Devices:"
    $systemDevices = Get-CimInstance Win32_SystemDriver | Where-Object {$_.Name -match "Intel|AMD|NVIDIA|Realtek|Broadcom"} | Select-Object Name, State, Status | Sort-Object Name
    if ($systemDevices) {
        $systemDevices | Format-Table -AutoSize
    }
    
    # PCI devices (key system components)
    Write-Output "Key PCI Devices:"
    $pciDevices = Get-CimInstance Win32_PnPEntity | Where-Object {
        $_.PNPDeviceID -like "PCI\*" -and 
        ($_.Name -match "Intel|AMD|NVIDIA|Realtek|Broadcom|Controller|Bridge")
    } | Select-Object Name, Status, PNPDeviceID | Sort-Object Name
    
    if ($pciDevices) {
        foreach ($dev in $pciDevices) {
            Write-Output "  $($dev.Name) - $($dev.Status)"
        }
    }
} catch { Write-Warning "Could not query chipset information: $($_.Exception.Message)" }
Write-Output "`n"

Write-Output "=== 18. Recent Critical Events ==="
try {
    # Get recent critical events that might indicate hardware issues
    $criticalEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'System'
        Level = 1,2  # Critical and Error
        StartTime = (Get-Date).AddDays(-3)
    } -MaxEvents 20 -ErrorAction SilentlyContinue | 
    Where-Object {$_.ProviderName -match "Kernel|Hardware|PnP|Power|Display|USB|Disk"}
    
    if ($criticalEvents) {
        Write-Output "Recent Critical/Error Events (last 3 days):"
        foreach ($critEvent in $criticalEvents) {
            Write-Output "  $(Get-Date $critEvent.TimeCreated -Format 'MM-dd HH:mm') ID:$($critEvent.Id) $($critEvent.ProviderName)"
            Write-Output "    $($critEvent.LevelDisplayName): $($critEvent.Message.Split([Environment]::NewLine)[0])"
        }
    } else {
        Write-Output "No recent critical events found."
    }
} catch { Write-Warning "Could not query recent events: $($_.Exception.Message)" }
Write-Output "`n"

Write-Output "=== Debug Info Collection Completed ==="
