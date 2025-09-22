# Windows Sleep Debug

A PowerShell script to collect diagnostic information about Windows sleep, hibernate, and wake failures.
Useful for troubleshooting issues such as:

- System not resuming from sleep (black screen, freeze, forced shutdown)
- Kernel-Power (Event ID 41) unexpected shutdowns
- Driver or device problems during resume

## What it collects

### System & Hardware Information
- Complete system profile: manufacturer, model, BIOS version/date, memory, processor
- Power capabilities: Modern Standby support, hibernate availability, platform role
- Memory modules: size, type, speed, manufacturer details
- Storage devices: models, interfaces, capacity
- Chipset and PCI device information
- Recent critical hardware/power events (last 3 days)

### Power & Sleep Diagnostics
- Last wake source: `powercfg /lastwake`
- Devices allowed to wake and programmable to wake: `powercfg /devicequery wake_armed`, `wake_programmable`
- Current power requests blocking sleep: `powercfg /requests`
- Available sleep states: `powercfg /a`
- Wake timers: `powercfg /waketimers`
- Wake history analysis: last 10 wake events with sources and timestamps
- USB & Sleep power settings: USB Selective Suspend, USB 3 Link Power Management, Hybrid Sleep, Allow Wake Timers
- Fast Startup status (HiberbootEnabled)

### Display & Graphics
- Display/GPU and Monitor info: `Win32_VideoController`, PnP Display/Monitor devices with driver versions
- GPU power management settings and wake capabilities
- Connected display information: connection types, active status
- Graphics adapter power settings and capabilities

### Network & USB Analysis
- Network adapter detailed analysis: driver info, Wake-on-LAN settings, link speeds
- USB controllers and wake-capable USB devices
- Device-specific wake capabilities

### Event Log Analysis
- Enhanced Event Viewer logs (last 7 days) from System and Application logs
- Filtered events: Kernel-Power, Power-Troubleshooter, DriverFrameworks, Display/Graphics/DWM-related
- Wake source pattern analysis from recent events

### Power Management
- BIOS/UEFI device wake capabilities: `MSPower_DeviceWakeEnable`
- Active power plan details: current scheme and key display/video timeouts
- Comprehensive power setting analysis

### Reports Generated
- Sleep Study report (HTML) - if supported by system
- Energy report (HTML) - 60-second power efficiency analysis

All outputs are saved to a chosen folder, with timestamped filenames.

## Requirements

- Windows 10/11
- PowerShell (Windows PowerShell 5.1 or PowerShell 7+)
- Run the script as Administrator

## Usage

1) Download the script:

- [`SleepDebug.ps1`](./SleepDebug.ps1)

2) Open PowerShell as Administrator.

3) If scripts are blocked, allow them temporarily:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```

4) Run the script. By default, outputs go to a `reports` folder next to the script:

```powershell
.\SleepDebug.ps1
```

5) Or choose a custom output folder with `-OutDir`:

```powershell
.\SleepDebug.ps1 -OutDir "D:\Temp\SleepDebug"
```

The script will create the folder if it doesn't exist and print the resolved path.

## Outputs

Files written to the output folder (examples):

- `SleepDebug-Report-YYYYMMDD-HHMMSS.txt` — **Comprehensive diagnostic report** (all system info, power diagnostics, device analysis)
- `sleepstudy-report-YYYYMMDD-HHMMSS.html` — Sleep Study report
- `energy-report-YYYYMMDD-HHMMSS.html` — Energy report (60s collection)
- `SleepDebug-Events-YYYYMMDD-HHMMSS.xml` — Exported events (machine-readable)
- `SleepDebug-Events-YYYYMMDD-HHMMSS.txt` — Exported events (human-readable table)

Additionally, all information is displayed in the console during script execution.

**For LLM Analysis**: The script generates a comprehensive text report (`SleepDebug-Report-YYYYMMDD-HHMMSS.txt`) containing all system information, hardware specifications, driver versions, BIOS details, power settings, and diagnostic results. This single file provides complete context for AI-powered troubleshooting and accurate diagnosis of sleep/wake issues. Simply upload this report along with any HTML files for comprehensive analysis.

Note: On some systems without Modern/Connected Standby, `powercfg /sleepstudy` may not generate a detailed report. The script will handle this gracefully and provide alternative guidance.

## Recommendations for Event ID 41 (Checkpoint ~16)

If you’re seeing black screen after sleep and Event 41 with Checkpoint around 16, this often points at resume/graphics handoff issues:

1. Temporarily disable Fast Startup to test stability:
   - `powercfg /h off`
2. Update display/GPU drivers from OEM (NVIDIA/AMD/Intel) and motherboard chipset drivers.
3. Test with Hybrid Sleep off (AC):
   - `powercfg /setacvalueindex SCHEME_CURRENT SUB_SLEEP HYBRIDSLEEP 0`
   - `powercfg /setactive SCHEME_CURRENT`
4. Test with USB Selective Suspend disabled (AC):
   - `powercfg /setacvalueindex SCHEME_CURRENT SUB_USB USBSELECTIVESUSPEND 0`
   - `powercfg /setactive SCHEME_CURRENT`
5. Verify wake sources and disable unwanted device wake capability in Device Manager.
6. Try a different display cable/port, check for BIOS/UEFI updates, and as a test only, consider toggling certain power features (e.g., C-states/ERP) to see if behavior changes.

## Privacy

Exported event logs may contain application names and system details. Review before sharing.
