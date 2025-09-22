# Windows Sleep Debug

A PowerShell script to collect diagnostic information about Windows sleep, hibernate, and wake failures.
Useful for troubleshooting issues such as:

- System not resuming from sleep (black screen, freeze, forced shutdown)
- Kernel-Power (Event ID 41) unexpected shutdowns
- Driver or device problems during resume

## What it collects

- Last wake source: `powercfg /lastwake`
- Devices allowed to wake and programmable to wake: `powercfg /devicequery wake_armed`, `wake_programmable`
- Current power requests blocking sleep: `powercfg /requests`
- Available sleep states: `powercfg /a`
- Wake timers: `powercfg /waketimers`
- Display/GPU and Monitor info: `Win32_VideoController`, PnP Display/Monitor devices
- USB & Sleep power settings: USB Selective Suspend, USB 3 Link Power Management (if present), Hybrid Sleep, Allow Wake Timers
- Fast Startup status (HiberbootEnabled)
- Enhanced Event Viewer logs (last 7 days) from System and Application (Kernel-Power, Power-Troubleshooter, DriverFrameworks, Display/Graphics/DWM-related)
- BIOS/UEFI device wake capabilities: `MSPower_DeviceWakeEnable`
- Active power plan details: current scheme and key SUB_VIDEO timeouts
- Reports:
  - Sleep Study report (HTML)
  - Energy report (HTML)

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

- `sleepstudy-report-YYYYMMDD-HHMMSS.html` — Sleep Study report
- `energy-report-YYYYMMDD-HHMMSS.html` — Energy report (60s collection)
- `SleepDebug-Events-YYYYMMDD-HHMMSS.xml` — Exported events (machine-readable)
- `SleepDebug-Events-YYYYMMDD-HHMMSS.txt` — Exported events (human-readable table)

Additionally, the console displays the results of `powercfg` queries, device lists, and statuses to help spot issues quickly.

Note: On some systems without Modern/Connected Standby, `powercfg /sleepstudy` may not generate a detailed report. The script will still attempt to copy the report if available.

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
