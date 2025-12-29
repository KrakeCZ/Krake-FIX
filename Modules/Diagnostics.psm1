# ═══════════════════════════════════════════════════════════════════════════
# Module: Diagnostics.psm1
# ═══════════════════════════════════════════════════════════════════════════
# Project:      KRAKE-FIX v2 Modular
# Version:      2.0.0
# Author:       KRAKE-FIX Team
# Created:      2025-10-29
# Last Updated: 2025-10-29
# ═══════════════════════════════════════════════════════════════════════════
# Description:  System diagnostics, BSOD analysis, event logs, dump management
# Category:     Diagnostics
# Dependencies: Core.psm1 (Write-CoreLog)
# Admin Rights: Required (for system logs, dump access)
# ═══════════════════════════════════════════════════════════════════════════
# ⚠️  SECURITY & COMPLIANCE NOTICE
# ═══════════════════════════════════════════════════════════════════════════
# • This module reads system diagnostics and crash dumps
# • Designed for troubleshooting and analysis purposes
# • No system modifications (read-only operations)
# • BSI4 compliant: Input validation, error handling, audit logging
# ═══════════════════════════════════════════════════════════════════════════

#Requires -Version 5.1
#Requires -RunAsAdministrator

using namespace System.Management.Automation
function Invoke-ModuleEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $ModuleContext
    )

    if ($null -eq $ModuleContext) {
        throw [System.ArgumentNullException]::new('ModuleContext')
    }

    Show-DiagnosticsMenu
}
# ───────────────────────────────────────────────────────────────────────────
# MODULE INITIALIZATION
# ───────────────────────────────────────────────────────────────────────────

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Module-level variables (private)
$script:ModuleName = 'Diagnostics'
$script:ModuleVersion = '2.0.0'

# Use Write-CoreLog from already-loaded Core module (loaded by Main.ps1)
# DO NOT re-import Core.psm1 here - causes scope conflicts!
if (-not (Get-Command Write-CoreLog -ErrorAction SilentlyContinue)) {
    Write-Warning "Core.psm1 not loaded. Diagnostics module requires Core module."
}

# Utils.psm1 eliminated - backup utilities now in Recovery.psm1

# ───────────────────────────────────────────────────────────────────────────
# PRIVATE HELPER FUNCTIONS
# ───────────────────────────────────────────────────────────────────────────

# (Reserved for internal helpers)

# ───────────────────────────────────────────────────────────────────────────
# DIAGNOSTIC MENU FUNCTIONS
# ───────────────────────────────────────────────────────────────────────────

function Show-DiagHeader {
    <#
    .SYNOPSIS
        Zobrazí diagnostický header s HW informacemi.
    
    .DESCRIPTION
        Zobrazí kompaktní přehled CPU/RAM/GPU/Disk/Network.
        Optimalizováno pro rychlost - používá předem načtená data.
    
    .PARAMETER Data
        Hashtable s HW daty z Get-HWStatus (Utils.psm1).
    
    .EXAMPLE
        $hwData = Get-HWStatus
        Show-DiagHeader -Data $hwData
    
    .NOTES
        - Volá se z Show-DiagnosticsMenu
        - Data jsou načtena JEDNOU při vstupu do menu
        - Refresh pouze na vyžádání ([/] klávesa)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Data
    )
    
    try {
        Clear-Host
        Write-Host "===============================================================================" -ForegroundColor Cyan

        $cpuValue = 'N/A'
        if ($Data.ContainsKey('CPU') -and -not [string]::IsNullOrWhiteSpace([string]$Data['CPU'])) {
            $cpuValue = [string]$Data['CPU']
        }
        elseif ($Data.ContainsKey('CPUName') -and -not [string]::IsNullOrWhiteSpace([string]$Data['CPUName'])) {
            $cpuValue = [string]$Data['CPUName']
        }
        elseif ($Data.ContainsKey('Processor') -and -not [string]::IsNullOrWhiteSpace([string]$Data['Processor'])) {
            $cpuValue = [string]$Data['Processor']
        }
        Write-Host (" CPU: {0}" -f $cpuValue) -ForegroundColor White

        $ramUsed   = if ($Data.ContainsKey('RAMUsed')) { $Data['RAMUsed'] } else { $null }
        $ramTotal  = if ($Data.ContainsKey('RAMTotal')) { $Data['RAMTotal'] } else { $null }
        $ramPct    = if ($Data.ContainsKey('RAMPct')) { $Data['RAMPct'] } else { $null }
        $ramInfo   = $null
        if ($Data.ContainsKey('RAMInfo') -and -not [string]::IsNullOrWhiteSpace([string]$Data['RAMInfo'])) {
            $ramInfo = [string]$Data['RAMInfo']
        }
        elseif ($Data.ContainsKey('RAMSpeed') -and -not [string]::IsNullOrWhiteSpace([string]$Data['RAMSpeed'])) {
            $ramInfo = [string]$Data['RAMSpeed']
        }
        elseif ($Data.ContainsKey('RAMType') -and -not [string]::IsNullOrWhiteSpace([string]$Data['RAMType'])) {
            $ramInfo = [string]$Data['RAMType']
        }

        if ($null -ne $ramUsed -and $null -ne $ramTotal -and $null -ne $ramPct) {
            $ramLine = " RAM: {0}/{1} GB ({2}%)" -f $ramUsed, $ramTotal, $ramPct
            if ($null -ne $ramInfo) {
                $ramLine = "$ramLine | $ramInfo"
            }
            Write-Host $ramLine -ForegroundColor White
        }
        elseif ($null -ne $ramInfo) {
            Write-Host (" RAM: {0}" -f $ramInfo) -ForegroundColor White
        }

        if ($null -ne $ramInfo) {
            if ($ramInfo -match '\[X\]\s+JEDEC') {
                Write-Host "  -> JEDEC profil: výchozí SPD bez XMP" -ForegroundColor DarkGray
            }
            elseif ($ramInfo -match '\[OK\]\s+XMP') {
                Write-Host "  -> XMP aktivní: načtený přetaktovací profil" -ForegroundColor DarkGray
            }
        }

        $gpuValue = $null
        if ($Data.ContainsKey('GPU') -and -not [string]::IsNullOrWhiteSpace([string]$Data['GPU'])) {
            $gpuValue = [string]$Data['GPU']
        }
        elseif ($Data.ContainsKey('GPUName') -and -not [string]::IsNullOrWhiteSpace([string]$Data['GPUName'])) {
            $gpuValue = [string]$Data['GPUName']
        }
        if ($null -ne $gpuValue -and $gpuValue -ne 'N/A') {
            Write-Host (" GPU: {0}" -f $gpuValue) -ForegroundColor White
        }

        if ($Data.ContainsKey('GPUIntegrated')) {
            $igpuValue = $Data['GPUIntegrated']
            if ($null -ne $igpuValue -and -not [string]::IsNullOrWhiteSpace([string]$igpuValue) -and $igpuValue -ne 'N/A' -and $igpuValue -ne $gpuValue) {
                Write-Host (" iGPU: {0}" -f $igpuValue) -ForegroundColor White
            }
        }

        if ($Data.ContainsKey('GPUVRAM')) {
            $gpuVramValue = $Data['GPUVRAM']
            if ($null -ne $gpuVramValue -and -not [string]::IsNullOrWhiteSpace([string]$gpuVramValue) -and $gpuVramValue -ne 'N/A') {
                Write-Host (" VRAM: {0}" -f $gpuVramValue) -ForegroundColor White
            }
        }

        if ($Data.ContainsKey('GPUIntegratedVRAM')) {
            $igpuVramValue = $Data['GPUIntegratedVRAM']
            if ($null -ne $igpuVramValue -and -not [string]::IsNullOrWhiteSpace([string]$igpuVramValue) -and $igpuVramValue -ne 'N/A' -and $Data.ContainsKey('GPUIntegrated') -and $Data['GPUIntegrated'] -ne $gpuValue) {
                Write-Host (" iGPU VRAM: {0}" -f $igpuVramValue) -ForegroundColor White
            }
        }

        if ($Data.ContainsKey('DiskInfo')) {
            $diskInfo = $Data['DiskInfo']
            if ($null -ne $diskInfo -and $diskInfo -ne 'N/A' -and -not [string]::IsNullOrWhiteSpace([string]$diskInfo)) {
                Write-Host (" Disk C: {0}" -f $diskInfo) -ForegroundColor White
            }
        }

        if ($Data.ContainsKey('NetworkInfo')) {
            $networkData = $Data['NetworkInfo']
            if ($null -ne $networkData) {
                if ($networkData -isnot [System.Collections.IEnumerable] -or $networkData -is [string]) {
                    $networkData = @($networkData)
                }
                foreach ($netLine in $networkData) {
                    if (-not [string]::IsNullOrWhiteSpace([string]$netLine)) {
                        Write-Host (" {0}" -f $netLine) -ForegroundColor White
                    }
                }
            }
        }

        Write-Host "===============================================================================" -ForegroundColor Cyan

        Write-CoreLog "Diagnostic header displayed" -Level DEBUG

    } catch {
        Write-CoreLog "Failed to display diagnostic header: $($_.Exception.Message)" -Level ERROR
        Write-Host "===============================================================================" -ForegroundColor Cyan
        Write-Host " Diagnostic Header - Error loading data" -ForegroundColor Red
        Write-Host "===============================================================================" -ForegroundColor Cyan
    }
}

function Show-DiagnosticsMenu {
    <#
    .SYNOPSIS
        Hlavní diagnostické menu s submenu pro různé diagnostické funkce.
    
    .DESCRIPTION
        Zobrazí interaktivní menu pro:
        - Statickou diagnostiku (snapshot systému)
        - Prohlížení system/application logů
        - BSOD analýzu
        - Dump management
        
        HW data jsou načtena JEDNOU při vstupu, refresh pouze na [/].
    
    .EXAMPLE
        Show-DiagnosticsMenu
    
    .NOTES
        - Vyžaduje Utils.psm1 (Get-HWStatus)
        - Optimalizováno pro rychlost (cached HW data)
        - Všechna submenu ukončují pomocí [Q]
    #>
    [CmdletBinding()]
    param()
    
    Write-CoreLog "Entering diagnostics menu" -Level INFO
    
    # Načíst HW data POUZE JEDNOU při vstupu
    try {
        $hwData = Get-HWStatus
    } catch {
        Write-CoreLog "Failed to get HW status: $($_.Exception.Message)" -Level WARNING
        $hwData = @{
            CPU = "N/A"
            RAMUsed = 0
            RAMTotal = 0
            RAMPct = 0
            RAMInfo = "N/A"
            RAMModuleSummary = "N/A"
            RAMTiming = "N/A"
            RAMTimingNote = "SPD časování není dostupné (vyžaduje přístup k SPD)"
            RAMVoltage = "N/A"
            GPU = "N/A"
            GPUVRAM = "N/A"
            GPUIntegrated = "N/A"
            GPUIntegratedVRAM = "N/A"
            DiskInfo = "N/A"
            NetworkInfo = @()
            ServicesRunning = 0
            ServicesTotal = 0
        }
    }
    
    $loop = $true
    while ($loop) {
        # Zobrazit header (bez nového WMI dotazu)
        Show-DiagHeader -Data $hwData
        
        Write-Host ""
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host "  🧠 DIAGNOSTICKE MENU" -ForegroundColor Yellow
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "[1] Staticka diagnostika (Snapshot systemu)" -ForegroundColor White
        Write-Host "──────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "[2] Zobrazit systemove udalosti (System + Application)" -ForegroundColor White
        Write-Host "[3] Zobrazit posledni BSOD / BugCheck" -ForegroundColor White
        Write-Host "[4] Analyzovat posledni dump (.dmp) – BSOD Analyzer" -ForegroundColor White
        Write-Host "[5] Nastaveni rezimu BSOD dumpu" -ForegroundColor White
        Write-Host "───────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "[6] Vymazat stare dumpy (!POZOR!)" -ForegroundColor Red
        Write-Host "───────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "[7] Exportovat logy do souboru" -ForegroundColor White
        Write-Host "[8] Kopirovat dumpy na plochu (manualne)" -ForegroundColor White
        Write-Host "[9] Smart-Dump Summary (rychla analyza vsech dumpu)" -ForegroundColor White
        Write-Host "──────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "[/] Okamzita obnova statickych udaju" -ForegroundColor White
        Write-Host "[Q] Navrat do hlavniho menu" -ForegroundColor Gray
        Write-Host "══════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        
        $choice = Read-Host "Vyber moznost (1-9, /, Q)"
        
        switch ($choice) {
            '1' { 
                Write-CoreLog "User selected: Static diagnostics" -Level INFO
                Show-StaticDiagnostics
                Start-Sleep -Milliseconds 100
            }
            '2' { 
                Write-CoreLog "User selected: System logs" -Level INFO
                Show-SystemLogs
                Start-Sleep -Milliseconds 100
            }
            '3' { 
                Write-CoreLog "User selected: Last BSOD" -Level INFO
                Show-LastBSOD
                Start-Sleep -Milliseconds 100
            }
            '4' { 
                Write-CoreLog "User selected: Dump analyzer" -Level INFO
                Show-DumpAnalyzer
                Start-Sleep -Milliseconds 100
            }
            '5' { 
                Write-CoreLog "User selected: BSOD dump mode" -Level INFO
                Show-BSODDumpMode
                Start-Sleep -Milliseconds 100
            }
            '6' { 
                Write-CoreLog "User selected: Clear dumps" -Level WARNING
                Clear-Dumps
                Start-Sleep -Milliseconds 100
            }
            '7' { 
                Write-CoreLog "User selected: Export system logs" -Level INFO
                Export-SystemLogs
                Start-Sleep -Milliseconds 100
            }
            '8' { 
                Write-CoreLog "User selected: Copy dumps to desktop" -Level INFO
                Copy-DumpsToDesktop
                Start-Sleep -Milliseconds 100
            }
            '9' { 
                Write-CoreLog "User selected: Smart dump summary" -Level INFO
                Show-SmartDumpSummary
                Start-Sleep -Milliseconds 100
            }
            '/' { 
                # Okamžitý refresh - ZNOVU NAČÍST WMI DATA!
                Write-CoreLog "User requested HW data refresh" -Level INFO
                try {
                    $hwData = Get-HWStatus
                } catch {
                    Write-CoreLog "HW refresh failed: $($_.Exception.Message)" -Level WARNING
                }
                continue
            }
            'Q' { 
                Write-CoreLog "User exited diagnostics menu" -Level INFO
                $loop = $false 
            }
            'q' { 
                Write-CoreLog "User exited diagnostics menu" -Level INFO
                $loop = $false 
            }
            default {
                Write-Host "Neplatna volba – zkus znovu." -ForegroundColor DarkGray
                Start-Sleep -Seconds 1
            }
        }
    }
}

# ───────────────────────────────────────────────────────────────────────────
# STATIC DIAGNOSTIC FUNCTIONS
# ───────────────────────────────────────────────────────────────────────────

function Show-StaticDiagnostics {
    <#
    .SYNOPSIS
        Zobrazí statickou diagnostiku - jednorázový snapshot systému.
    
    .DESCRIPTION
        Zobrazí detailní přehled:
        - OS (verze, build, uptime)
        - CPU (model, jádra/vlákna)
        - RAM (použití, procenta)
        - GPU (model, VRAM, rozlišení)
        - Disk (využití)
        - Síť (aktivní adaptéry)
    
    .EXAMPLE
        Show-StaticDiagnostics
    
    .NOTES
        - Read-only operace
        - Využívá CIM pro rychlost
        - Ukončení pomocí [Q]
    #>
    [CmdletBinding()]
    param()
    
    Write-CoreLog "Displaying static diagnostics" -Level INFO
    
    Clear-Host
    Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "🧠 STATICKA DIAGNOSTIKA – SNAPSHOT SYSTEMU" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""

    try {
        $hwSnapshot = $null
        try {
            $hwSnapshot = Get-HWStatus
        } catch {
            Write-CoreLog "Static diagnostics snapshot failed: $($_.Exception.Message)" -Level WARNING
        }

        # OS
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
        if ($os) {
            Write-Host ("💻 System: {0}" -f $os.Caption)
            Write-Host ("🧱 Build:  {0} ({1})" -f $os.Version, $os.BuildNumber)
            Write-Host ("🕒 Uptime: {0:dd}d {0:hh}h {0:mm}m" -f ((Get-Date) - $os.LastBootUpTime))
        }

        # CPU
        $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cpu) {
            Write-Host ("🧩 CPU: {0}" -f $cpu.Name)
            Write-Host ("🔧 Jader/Vlaken: {0}/{1}" -f $cpu.NumberOfCores, $cpu.NumberOfLogicalProcessors)
        }

        # RAM
        if ($os) {
            $ramTotal = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
            $ramUsed = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1MB, 1)
            $ramPct = [math]::Round(($ramUsed / $ramTotal) * 100, 0)
            Write-Host ("💾 RAM: {0} / {1} GB  ({2}%)" -f $ramUsed, $ramTotal, $ramPct)
        }

        if ($hwSnapshot -and $hwSnapshot.RAMInfo -and $hwSnapshot.RAMInfo -ne 'N/A') {
            Write-Host ("    ↳ Profil: {0}" -f $hwSnapshot.RAMInfo) -ForegroundColor Gray
        }
        if ($hwSnapshot -and $hwSnapshot.RAMVoltage -and $hwSnapshot.RAMVoltage -ne 'N/A') {
            Write-Host ("    ↳ Napětí: {0}" -f $hwSnapshot.RAMVoltage) -ForegroundColor Gray
        }
        if ($hwSnapshot -and $hwSnapshot.RAMTiming -and $hwSnapshot.RAMTiming -ne 'N/A') {
            Write-Host ("⏱️ RAM tCK: {0}" -f $hwSnapshot.RAMTiming) -ForegroundColor Gray
        }
        elseif ($hwSnapshot -and $hwSnapshot.RAMTimingNote) {
            Write-Host ("ℹ️ RAM Timing: {0}" -f $hwSnapshot.RAMTimingNote) -ForegroundColor DarkGray
        }
        if ($hwSnapshot -and $hwSnapshot.RAMModuleSummary -and $hwSnapshot.RAMModuleSummary -ne 'N/A') {
            Write-Host ("🧠 Moduly: {0}" -f $hwSnapshot.RAMModuleSummary) -ForegroundColor Gray
        }

        # GPU
        $gpuCollection = Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue
        $primaryGpu = $null
        if ($gpuCollection) {
            $primaryGpu = $gpuCollection | Sort-Object -Property @{ Expression = { if ($_.AdapterRAM) { [int64]$_.AdapterRAM } else { 0 } } ; Descending = $true } | Select-Object -First 1
        }

        if ($hwSnapshot -and $hwSnapshot.GPUName -and $hwSnapshot.GPUName -ne 'N/A') {
            Write-Host ("🎮 GPU: {0}" -f $hwSnapshot.GPUName)
            if ($hwSnapshot.GPUVRAM -and $hwSnapshot.GPUVRAM -ne 'N/A') {
                Write-Host ("📊 VRAM: {0}" -f $hwSnapshot.GPUVRAM) -ForegroundColor Gray
            }
        }
        elseif ($primaryGpu) {
            Write-Host ("🎮 GPU: {0}" -f $primaryGpu.Name)
            if ($primaryGpu.AdapterRAM -gt 0) {
                Write-Host ("📊 VRAM: {0:N1} GB" -f ($primaryGpu.AdapterRAM / 1GB)) -ForegroundColor Gray
            }
        }

        if ($hwSnapshot -and $hwSnapshot.GPUIntegrated -and $hwSnapshot.GPUIntegrated -ne 'N/A' -and $hwSnapshot.GPUIntegrated -ne $hwSnapshot.GPUName) {
            Write-Host ("🖼️ iGPU: {0}" -f $hwSnapshot.GPUIntegrated)
            if ($hwSnapshot.GPUIntegratedVRAM -and $hwSnapshot.GPUIntegratedVRAM -ne 'N/A') {
                Write-Host ("🖼️ VRAM (iGPU): {0}" -f $hwSnapshot.GPUIntegratedVRAM) -ForegroundColor Gray
            }
        }

        if ($primaryGpu -and $primaryGpu.CurrentHorizontalResolution -and $primaryGpu.CurrentVerticalResolution) {
            Write-Host ("🖥  Rozliseni: {0}x{1}" -f $primaryGpu.CurrentHorizontalResolution, $primaryGpu.CurrentVerticalResolution)
        }

        # Disk
        $disk = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($disk) {
            $used = [math]::Round(($disk.Size - $disk.FreeSpace) / 1GB, 1)
            $total = [math]::Round($disk.Size / 1GB, 1)
            $pct = if ($total -gt 0) { [math]::Round(($used/$total)*100,0) } else { 0 }
            Write-Host ("💽 Disk ({0}): {1}/{2} GB  ({3}%)" -f $disk.DeviceID, $used, $total, $pct)
        }

        # Síť
        $net = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
        if ($net) {
            Write-Host ("🌐 Sit: {0} ({1}) @ {2}" -f $net.Name, $net.InterfaceDescription, $net.LinkSpeed)
        } else {
            Write-Host "🌐 Sit: Neni aktivni adapter" -ForegroundColor DarkGray
        }

        if ($hwSnapshot -and $hwSnapshot.ServicesTotal -gt 0) {
            Write-Host ("🛠️ Služby (běží/celkem): {0}/{1}" -f $hwSnapshot.ServicesRunning, $hwSnapshot.ServicesTotal)
        }
        
        Write-CoreLog "Static diagnostics displayed successfully" -Level SUCCESS
        
    } catch {
        Write-CoreLog "Error displaying static diagnostics: $($_.Exception.Message)" -Level ERROR
        Write-Host "Chyba při načítání diagnostických dat." -ForegroundColor Red
    }

    Write-Host ""
    Write-Host "────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "[Q] Zpet do menu" -ForegroundColor Red
    Write-Host ""
    $key = Read-Host "Stiskni Q pro navrat"
    if ($key -eq 'Q' -or $key -eq 'q' -or $key -eq '') { return }
}

function Show-SystemLogs {
    <#
    .SYNOPSIS
        Zobrazí systemové události (System + Application log).
    
    .DESCRIPTION
        Načte a zobrazí posledních 10 událostí z:
        - System log
        - Application log
    
    .EXAMPLE
        Show-SystemLogs
    
    .NOTES
        - Data jsou načtena PŘED Clear-Host pro rychlost
        - Read-only operace
        - Ukončení pomocí [Q]
    #>
    [CmdletBinding()]
    param()
    
    Write-CoreLog "Displaying system logs" -Level INFO
    
    # Načíst data PŘED clear-host
    try {
        $system = Get-WinEvent -LogName System -MaxEvents 10 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, Message
        $app = Get-WinEvent -LogName Application -MaxEvents 10 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, Message
    } catch {
        Write-CoreLog "Failed to read event logs: $($_.Exception.Message)" -Level WARNING
        $system = $null
        $app = $null
    }
    
    Clear-Host
    Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "🧾 SYSTEMOVE UDALOSTI – System & Application" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "`n🖥 System Log:" -ForegroundColor Green
    if ($system) {
        $system | Format-Table -AutoSize
    } else {
        Write-Host "  Zadne udalosti." -ForegroundColor DarkGray
    }
    
    Write-Host "`n💡 Application Log:" -ForegroundColor Green
    if ($app) {
        $app | Format-Table -AutoSize
    } else {
        Write-Host "  Zadne udalosti." -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "[Q] Zpet do menu" -ForegroundColor Red
    Write-Host ""
    $key = Read-Host "Stiskni Q pro navrat"
    if ($key -eq 'Q' -or $key -eq 'q' -or $key -eq '') { return }
}

function Show-LastBSOD {
    <#
    .SYNOPSIS
        Zobrazí poslední BSOD / BugCheck události.
    
    .DESCRIPTION
        Vyhledá posledních 5 BSOD událostí v System logu:
        - Event ID: 1001
        - Provider: Microsoft-Windows-WER-SystemErrorReporting
    
    .EXAMPLE
        Show-LastBSOD
    
    .NOTES
        - Data jsou načtena PŘED Clear-Host
        - Read-only operace
        - Ukončení pomocí [Q]
    #>
    [CmdletBinding()]
    param()
    
    Write-CoreLog "Displaying last BSOD events" -Level INFO
    
    # Načíst data PŘED clear-host
    try {
        $bsod = Get-WinEvent -LogName System -ErrorAction SilentlyContinue | 
                Where-Object { $_.Id -eq 1001 -and $_.ProviderName -eq "Microsoft-Windows-WER-SystemErrorReporting" } | 
                Select-Object -First 5
    } catch {
        Write-CoreLog "Failed to read BSOD events: $($_.Exception.Message)" -Level WARNING
        $bsod = $null
    }
    
    Clear-Host
    Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "💥 POSLEDNI BSOD / BUGCHECK" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""

    if (-not $bsod) {
        Write-Host "Zadne BSOD udalosti nenalezeny." -ForegroundColor DarkGray
    } else {
        $bsod | ForEach-Object {
            Write-Host ("🕒 {0} | {1}" -f $_.TimeCreated, $_.Message.Split("`n")[0])
        }
        Write-CoreLog "Found $($bsod.Count) BSOD events" -Level INFO
    }

    Write-Host ""
    Write-Host "[Q] Zpet do menu" -ForegroundColor Red
    Write-Host ""
    $key = Read-Host "Stiskni Q pro navrat"
    if ($key -eq 'Q' -or $key -eq 'q' -or $key -eq '') { return }
}

# ───────────────────────────────────────────────────────────────────────────
# DUMP ANALYSIS FUNCTIONS
# ───────────────────────────────────────────────────────────────────────────

function Show-DumpAnalyzer {
    <#
    .SYNOPSIS
        Analyzuje poslední dump (.dmp) soubor.
    
    .DESCRIPTION
        Načte a parsuje poslední minidump soubor:
        - BugCheck code
        - Problémový modul (.sys)
        - Timestamp
    
    .EXAMPLE
        Show-DumpAnalyzer
    
    .NOTES
        - Vyhledává v C:\Windows\Minidump
        - Parsuje binární strukturu dump souboru
        - Read-only operace
    #>
    [CmdletBinding()]
    param()
    
    Write-CoreLog "Starting dump analyzer" -Level INFO
    
    # Načíst dump PŘED clear-host
    $dumpDir = "C:\Windows\Minidump"
    try {
        $dump = Get-ChildItem $dumpDir -Filter *.dmp -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    } catch {
        Write-CoreLog "Failed to access dump directory: $($_.Exception.Message)" -Level WARNING
        $dump = $null
    }
    
    Clear-Host
    Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "🧠 ANALYZA POSLEDNIHO DUMP SOUBORU" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""

    if (-not $dump) {
        Write-Host "❌ Nebyl nalezen zadny .dmp soubor v $dumpDir" -ForegroundColor DarkGray
        Write-CoreLog "No dump files found in $dumpDir" -Level WARNING
        Write-Host ""
        Write-Host "[Q] Zpet do menu" -ForegroundColor Red
        Write-Host ""
        $key = Read-Host "Stiskni Q pro navrat"
        return
    }

    Write-Host ("Analyzuji: {0}" -f $dump.FullName) -ForegroundColor Gray
    
    try {
        $bytes = Get-Content -Path $dump.FullName -Encoding Byte -TotalCount 512 -ErrorAction Stop
        if ($bytes) {
            $bug = [BitConverter]::ToUInt32($bytes[4..7],0)
            $text = [System.Text.Encoding]::ASCII.GetString($bytes)
            $mod = if ($text -match '([A-Za-z0-9_\-]+\.sys)') { $matches[1] } else { "Nezjisteno" }

            Write-Host ""
            Write-Host ("📘 Soubor: {0}" -f $dump.Name)
            Write-Host ("🧩 BugCheck: 0x{0:X8}" -f $bug)
            Write-Host ("🔍 Modul: {0}" -f $mod)
            Write-Host ("📅 Cas: {0}" -f $dump.LastWriteTime)
            
            Write-CoreLog "Dump analyzed: BugCheck=0x$($bug.ToString('X8')), Module=$mod" -Level SUCCESS
        } else {
            Write-Host "Chyba pri cteni souboru." -ForegroundColor Red
            Write-CoreLog "Failed to read dump file bytes" -Level ERROR
        }
    } catch {
        Write-Host "Chyba pri cteni souboru: $($_.Exception.Message)" -ForegroundColor Red
        Write-CoreLog "Dump analysis failed: $($_.Exception.Message)" -Level ERROR
    }

    Write-Host ""
    Write-Host "[Q] Zpet do menu" -ForegroundColor Red
    Write-Host ""
    $key = Read-Host "Stiskni Q pro navrat"
    if ($key -eq 'Q' -or $key -eq 'q' -or $key -eq '') { return }
}

function Show-SmartDumpSummary {
    <#
    .SYNOPSIS
        Rychlá analýza všech dump souborů.
    
    .DESCRIPTION
        Analyzuje všechny dump soubory v D-U-M-P-S složce na ploše:
        - BugCheck codes
        - Problémové moduly
        - Timestamps
        - Velikosti souborů
        
        Výsledky lze exportovat do logu.
    
    .EXAMPLE
        Show-SmartDumpSummary
    
    .NOTES
        - Vyžaduje předchozí spuštění Copy-DumpsToDesktop [8]
        - Hromadná analýza všech .dmp souborů
        - Optional export do CSV/LOG
    #>
    [CmdletBinding()]
    param()
    
    Write-CoreLog "Starting smart dump summary" -Level INFO
    
    Clear-Host
    Write-Host "🧠 SMART-DUMP SUMMARY - RYCHLA ANALYZA" -ForegroundColor Cyan
    Write-Host "────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "Hledam dump soubory..." -ForegroundColor Gray
    
    $dumpDir = [IO.Path]::Combine([Environment]::GetFolderPath("Desktop"), "D-U-M-P-S")
    if (-not (Test-Path $dumpDir)) {
        Write-Host "⚠ Slozka D-U-M-P-S nebyla nalezena. Pouzij nejprve volbu [8]." -ForegroundColor DarkGray
        Write-CoreLog "D-U-M-P-S folder not found" -Level WARNING
        Start-Sleep 2
        return
    }

    try {
        $dumps = Get-ChildItem $dumpDir -Filter *.dmp -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
    } catch {
        Write-CoreLog "Failed to enumerate dump files: $($_.Exception.Message)" -Level ERROR
        $dumps = $null
    }
    
    if (-not $dumps) {
        Write-Host "Zadne dumpy nebyly nalezeny." -ForegroundColor DarkGray
        Start-Sleep 1
        return
    }

    Write-Host "Nalezeno $($dumps.Count) souboru - analyzuji..." -ForegroundColor Cyan
    Write-Host ""

    $results = @()
    foreach ($dmp in $dumps) {
        try {
            $bytes = Get-Content -Path $dmp.FullName -Encoding Byte -TotalCount 512 -ErrorAction Stop
            $bug = [BitConverter]::ToUInt32($bytes[4..7],0)
            $text = [System.Text.Encoding]::ASCII.GetString($bytes)
            $mod  = if ($text -match '([A-Za-z0-9_\-]+\.sys)') { $matches[1] } else { "Nezjisteno" }

            $results += [PSCustomObject]@{
                Soubor   = $dmp.Name
                Datum    = $dmp.LastWriteTime
                BugCheck = ('0x{0:X8}' -f $bug)
                Modul    = $mod
                Velikost = ("{0:N2} MB" -f ($dmp.Length / 1MB))
            }
        } catch {
            $results += [PSCustomObject]@{
                Soubor   = $dmp.Name
                Datum    = $dmp.LastWriteTime
                BugCheck = "Chyba"
                Modul    = "Nepodarilo se cist"
                Velikost = ("{0:N2} MB" -f ($dmp.Length / 1MB))
            }
        }
    }

    $results | Sort-Object Datum -Descending | Format-Table -AutoSize
    
    Write-CoreLog "Analyzed $($results.Count) dump files" -Level SUCCESS
    
    Write-Host "`n💾 Exportovat vypis do souboru? (E/N)"
    $exp = Read-Host
    if ($exp -match '^[Ee]$') {
        try {
            $file = "C:\KRAKE-FIX\Logs\SmartDump_$((Get-Date).ToString('yyyyMMdd_HHmmss')).log"
            if (-not (Test-Path "C:\KRAKE-FIX\Logs")) { 
                New-Item -ItemType Directory -Path "C:\KRAKE-FIX\Logs" -Force | Out-Null 
            }
            $results | Out-File -FilePath $file -Encoding UTF8
            Write-Host "📄 Ulozeno do: $file" -ForegroundColor Green
            Write-CoreLog "Smart dump summary exported to: $file" -Level SUCCESS
        } catch {
            Write-Host "Chyba pri exportu: $($_.Exception.Message)" -ForegroundColor Red
            Write-CoreLog "Export failed: $($_.Exception.Message)" -Level ERROR
        }
    }
    
    Write-Host ""
    Write-Host "[Q] Zpet do menu" -ForegroundColor Red
    Write-Host ""
    $key = Read-Host "Stiskni Q pro navrat"
    if ($key -eq 'Q' -or $key -eq 'q' -or $key -eq '') { return }
}

function Show-BSODDumpMode {
    <#
    .SYNOPSIS
        Nastavení režimu BSOD dumpu.
    
    .DESCRIPTION
        Umožňuje konfiguraci Windows crash dump režimu:
        [0] Žádný výpis
        [1] Malý výpis (Minidump - výchozí)
        [2] Úplný výpis jádra (Kernel Dump)
        [3] Úplný výpis paměti (Complete Dump)
        
        Modifikuje: HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl
    
    .EXAMPLE
        Show-BSODDumpMode
    
    .NOTES
        - Vyžaduje administrátorská práva
        - Registry: CrashControl\CrashDumpEnabled
        - Restart není nutný
    #>
    [CmdletBinding()]
    param()
    
    Write-CoreLog "Entering BSOD dump mode configuration" -Level INFO
    
    while ($true) {
        Clear-Host
        Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "⚙ NASTAVENI REZIMU BSOD DUMPU" -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "[0] Zadny vypis"
        Write-Host "[1] Maly vypis (Minidump – vychozi)"
        Write-Host "[2] Uplny vypis jadra (Kernel Dump)"
        Write-Host "[3] Uplny vypis pameti (Complete Dump)"
        Write-Host "──────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "[Q] Zpet do menu" -ForegroundColor Red
        Write-Host ""
        $choice = Read-Host "Zvol rezim (0–3 nebo Q)"

        if ($choice -eq 'Q' -or $choice -eq 'q') {
            Write-CoreLog "User exited BSOD dump mode menu" -Level INFO
            return
        }

        if ($choice -notin @('0','1','2','3')) {
            Write-Host "❌ Neplatna volba!" -ForegroundColor Red
            Start-Sleep -Seconds 1
            continue
        }

        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl"
        $dumpType = [int]$choice

        try {
            Set-ItemProperty -Path $path -Name "CrashDumpEnabled" -Value $dumpType -Force -ErrorAction Stop
            Write-Host ""
            Write-Host "✅ Rezim vypisu zmenen na: $dumpType" -ForegroundColor Green
            Write-CoreLog "BSOD dump mode changed to: $dumpType" -Level SUCCESS
            Start-Sleep -Seconds 2
            return
        } catch {
            Write-Host ""
            Write-Host "⚠ Chyba pri zapisu do registru: $($_.Exception.Message)" -ForegroundColor Red
            Write-CoreLog "Failed to set dump mode: $($_.Exception.Message)" -Level ERROR
            Start-Sleep -Seconds 2
        }
    }
}

# ───────────────────────────────────────────────────────────────────────────
# DUMP OPERATIONS FUNCTIONS
# ───────────────────────────────────────────────────────────────────────────

function Clear-Dumps {
    <#
    .SYNOPSIS
        Vymaže staré dump soubory.
    
    .DESCRIPTION
        Odstraní všechny .dmp soubory z C:\Windows\Minidump.
        Vyžaduje potvrzení uživatele.
    
    .EXAMPLE
        Clear-Dumps
    
    .NOTES
        - DESTRUKTIVNÍ operace!
        - Vyžaduje administrátorská práva
        - Potvrzení před smazáním
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param()
    
    Write-CoreLog "Clear dumps requested" -Level WARNING
    
    $dumpDir = "C:\Windows\Minidump"
    
    try {
        $count = (Get-ChildItem $dumpDir -Filter *.dmp -ErrorAction SilentlyContinue).Count
    } catch {
        $count = 0
    }
    
    if ($count -eq 0) {
        Write-Host "Zadne dumpy k odstraneni." -ForegroundColor DarkGray
        Write-CoreLog "No dumps to clear" -Level INFO
        Start-Sleep 1
        return
    }
    
    Write-Host "⚠ Opravdu chces odstranit $count dump souboru? (Y/N)" -ForegroundColor Red
    $confirm = Read-Host
    
    if ($confirm -match '^[Yy]$') {
        try {
            Remove-Item "$dumpDir\*.dmp" -Force -ErrorAction Stop
            Write-Host "✅ Dump soubory odstraneeny." -ForegroundColor Green
            Write-CoreLog "$count dump files deleted" -Level WARNING
        } catch {
            Write-Host "❌ Chyba pri odstranovani: $($_.Exception.Message)" -ForegroundColor Red
            Write-CoreLog "Failed to delete dumps: $($_.Exception.Message)" -Level ERROR
        }
    } else {
        Write-Host "❎ Akce zrusena." -ForegroundColor DarkGray
        Write-CoreLog "Clear dumps cancelled by user" -Level INFO
    }
    
    Start-Sleep 1
}

function Export-SystemLogs {
    <#
    .SYNOPSIS
        Exportuje systemové logy do souboru.
    
    .DESCRIPTION
        Exportuje posledních 200 událostí ze System logu do textového souboru.
        Soubor je uložen v C:\KRAKE-FIX\Logs\ s timestampem.
    
    .EXAMPLE
        Export-SystemLogs
    
    .NOTES
        - Read-only operace
        - Auto-vytvoří adresář pokud neexistuje
        - UTF8 encoding
    #>
    [CmdletBinding()]
    param()
    
    Write-CoreLog "Exporting system logs" -Level INFO
    
    try {
        $dir = "C:\KRAKE-FIX\Logs"
        if (-not (Test-Path $dir)) { 
            New-Item -ItemType Directory -Path $dir -Force | Out-Null 
        }
        
        $file = "$dir\SystemLogs_$((Get-Date).ToString('yyyyMMdd_HHmmss')).txt"
        Get-WinEvent -LogName System -MaxEvents 200 -ErrorAction Stop | Out-File $file -Encoding UTF8
        
        Write-Host "📄 Logy exportovany do: $file" -ForegroundColor Green
        Write-CoreLog "System logs exported to: $file" -Level SUCCESS
        
    } catch {
        Write-Host "❌ Chyba pri exportu: $($_.Exception.Message)" -ForegroundColor Red
        Write-CoreLog "Log export failed: $($_.Exception.Message)" -Level ERROR
    }
    
    Start-Sleep 2
}

function Copy-DumpsToDesktop {
    <#
    .SYNOPSIS
        Zkopíruje dump soubory na plochu.
    
    .DESCRIPTION
        Zkopíruje všechny .dmp soubory z C:\Windows\Minidump
        do složky D-U-M-P-S na ploše.
    
    .EXAMPLE
        Copy-DumpsToDesktop
    
    .NOTES
        - Vyžaduje administrátorská práva (pro přístup k Minidump)
        - Auto-vytvoří cílovou složku
        - Read-only operace (kopírování, ne přesouvání)
    #>
    [CmdletBinding()]
    param()
    
    Write-CoreLog "Copying dumps to desktop" -Level INFO
    
    try {
        $dumpDir = "C:\Windows\Minidump"
        $target = [IO.Path]::Combine([Environment]::GetFolderPath("Desktop"), "D-U-M-P-S")
        
        if (-not (Test-Path $target)) { 
            New-Item -ItemType Directory -Path $target -Force | Out-Null 
        }
        
        Copy-Item "$dumpDir\*.dmp" -Destination $target -Force -ErrorAction Stop
        
        Write-Host "📂 Dumpy zkopirovany do: $target" -ForegroundColor Green
        Write-CoreLog "Dumps copied to: $target" -Level SUCCESS
        
    } catch {
        Write-Host "❌ Chyba pri kopirovani: $($_.Exception.Message)" -ForegroundColor Red
        Write-CoreLog "Dump copy failed: $($_.Exception.Message)" -Level ERROR
    }
    
    Start-Sleep 2
}

# ───────────────────────────────────────────────────────────────────────────
# INTEGRITY TEST FUNCTION
# ───────────────────────────────────────────────────────────────────────────

function Test-DiagnosticsIntegrity {
    <#
    .SYNOPSIS
        Závěrečný test všech diagnostických funkcí.
    
    .DESCRIPTION
        Ověří dostupnost všech funkcí diagnostického modulu:
        - Kontrola načtení funkcí
        - Kontrola administrátorských práv
        - Shrnutí prostředí (PowerShell verze, OS)
    
    .EXAMPLE
        Test-DiagnosticsIntegrity
    
    .OUTPUTS
        [bool] - $true pokud vše OK, $false pokud chybí funkce
    
    .NOTES
        - Diagnostický nástroj pro ověření integrity modulu
        - Používá se při vývoji/testování
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    Write-CoreLog "Running diagnostics integrity test" -Level INFO
    
    Clear-Host
    Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "🔍 TEST INTEGRITY DIAGNOSTICKEHO MODULU" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan

    $functions = @(
        'Get-ActiveNetworkInfo',
        'Get-HWStatus',
        'Show-HWHeader',
        'Show-DiagHeader',
        'Show-DiagnosticsMenu',
        'Show-StaticDiagnostics',
        'Show-SystemLogs',
        'Show-LastBSOD',
        'Show-DumpAnalyzer',
        'Show-BSODDumpMode',
        'Clear-Dumps',
        'Export-SystemLogs',
        'Copy-DumpsToDesktop',
        'Show-SmartDumpSummary',
        'Test-DiagnosticsIntegrity'
    )

    $missing = @()
    foreach ($fn in $functions) {
        if (-not (Get-Command $fn -ErrorAction SilentlyContinue)) {
            $missing += $fn
        }
    }

    if ($missing.Count -eq 0) {
        Write-Host "✅ Vsechny funkce diagnostiky jsou nacteny." -ForegroundColor Green
        Write-CoreLog "All diagnostic functions loaded successfully" -Level SUCCESS
    } else {
        Write-Host "⚠ Chybi funkce:" -ForegroundColor Red
        $missing | ForEach-Object { Write-Host "   • $_" -ForegroundColor DarkYellow }
        Write-CoreLog "Missing functions: $($missing -join ', ')" -Level ERROR
    }

    # Kontrola oprávnění
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ($isAdmin) {
            Write-Host "🧩 Bezi jako administrator – OK." -ForegroundColor Green
        } else {
            Write-Host "⚠ Skript neni spusten jako administrator." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "❌ Chyba pri kontrole opravneni." -ForegroundColor Red
    }

    # Shrnutí prostředí
    Write-Host "───────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "PowerShell: $($PSVersionTable.PSVersion)" -ForegroundColor Gray
    Write-Host "OS: $([System.Environment]::OSVersion.VersionString)" -ForegroundColor Gray
    Write-Host "Module: Diagnostics v$script:ModuleVersion" -ForegroundColor Gray
    Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
    
    Write-CoreLog "Integrity test completed. Missing: $($missing.Count)" -Level INFO
    
    return ($missing.Count -eq 0)
}

# ───────────────────────────────────────────────────────────────────────────
# MODULE INITIALIZATION COMPLETE
# ───────────────────────────────────────────────────────────────────────────

if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
    Write-CoreLog "Diagnostics module loaded successfully (v$script:ModuleVersion)" -Level SUCCESS
}

# ───────────────────────────────────────────────────────────────────────────
# MODULE EXPORT
# ───────────────────────────────────────────────────────────────────────────


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# UTILITY FUNCTIONS (merged from Utils.psm1)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

# ───────────────────────────────────────────────────────────────────────────
# NETWORK UTILITIES
# ───────────────────────────────────────────────────────────────────────────

function Get-ActiveNetworkInfo {
    <#
    .SYNOPSIS
        Získá kompaktní info o aktivních síťových adaptérech s DNS.
    
    .DESCRIPTION
        Vrací pole stringů s info o aktivních adaptérech (jen Status = Up, bez Virtual/VPN).
        Optimalizováno pro rychlost a spolehlivost.
    
    .OUTPUTS
        [string[]] Array of network adapter info strings.
    
    .EXAMPLE
        $netInfo = Get-ActiveNetworkInfo
        foreach ($line in $netInfo) {
            Write-Host $line
        }
        
        # OUTPUT:
        # LAN: Ethernet @ 1 Gbps | DNS: 8.8.8.8
        # WiFi: Wi-Fi @ 300 Mbps | DNS: DHCP
    
    .NOTES
        - Filters out virtual, VPN, loopback, and Bluetooth adapters
        - Retrieves DNS server addresses for each active adapter
        - Uses Get-NetAdapter and Get-DnsClientServerAddress
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    
    $networkInfo = @()
    
    try {
        Write-Verbose "Retrieving active network adapters..."
        
        $activeAdapters = Get-NetAdapter -ErrorAction Stop | Where-Object { 
            $_.Status -eq 'Up' -and 
            $_.InterfaceDescription -notmatch 'Virtual|VPN|Loopback|Bluetooth'
        }
        
        Write-Verbose "Found $($activeAdapters.Count) active adapters"
        
        foreach ($adapter in $activeAdapters) {
            # Získat DNS servery
            $dns = "DHCP"
            try {
                $dnsServers = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
                if ($null -ne $dnsServers -and $null -ne $dnsServers.ServerAddresses -and $dnsServers.ServerAddresses.Count -gt 0) {
                    $dns = $dnsServers.ServerAddresses[0]
                }
            } catch { 
                Write-Verbose "Failed to get DNS for adapter $($adapter.Name): $($_.Exception.Message)"
            }
            
            # Typ adaptéru
            $type = switch ($adapter.InterfaceType) {
                6   { "LAN" }
                71  { "WiFi" }
                default { "Net" }
            }
            
            $netLine = "{0}: {1} @ {2} | DNS: {3}" -f $type, $adapter.Name, $adapter.LinkSpeed, $dns
            $networkInfo += $netLine
            
            Write-Verbose "Added: $netLine"
        }
        
        Write-CoreLog "Retrieved network info for $($networkInfo.Count) adapters" -Level SUCCESS
        
    } catch {
        Write-CoreLog "Failed to retrieve network info: $($_.Exception.Message)" -Level ERROR
        Write-Error "Network info retrieval failed: $($_.Exception.Message)"
    }
    
    return $networkInfo
}

# ───────────────────────────────────────────────────────────────────────────
# HARDWARE STATUS FUNCTIONS
# ───────────────────────────────────────────────────────────────────────────

function Get-HWStatus {
    <#
    .SYNOPSIS
        Získá kompletní snapshot HW stavu (CPU/RAM/GPU/XMP/DPC/Uptime).
    
    .DESCRIPTION
        Vrací hashtable se všemi HW metrikami pro diagnostický header.
        Optimalizováno pro rychlost pomocí CIM (ne WMI).
        
        Podporuje multi-jazyk pro Performance Counters (EN/CZ/PL/SK/DE).
    
    .OUTPUTS
        [hashtable] s klíči:
        - CPUName, CPULoad, CPUTemp
        - RAMUsed, RAMTotal, RAMPercent, RAMType, RAMSpeed
        - GPUName, GPULoad, GPUTemp
        - DPCLatency
        - Uptime
        - Error (pokud došlo k chybě)
    
    .EXAMPLE
        $hw = Get-HWStatus
        if (-not $hw.Error) {
            Write-Host "CPU: $($hw.CPUName) | Load: $($hw.CPULoad)%"
            Write-Host "RAM: $($hw.RAMUsed) / $($hw.RAMTotal) GB ($($hw.RAMPercent)%)"
        }
    
    .NOTES
        - Používá Get-CimInstance místo Get-WmiObject (rychlejší)
        - Performance counters: \Processor(_Total)\% Processor Time
        - DPC latency: \Processor(_Total)\% DPC Time (mikrosek)
        - RAM info: Win32_PhysicalMemory (speed, type)
        - GPU info: Win32_VideoController
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    
    $hwStatus = @{
        CPUName           = "N/A"
        CPULoad           = 0
        CPUTemp           = "N/A"
        RAMUsed           = 0
        RAMTotal          = 0
        RAMPercent        = 0
        RAMPct            = 0
        RAMType           = "N/A"
        RAMSpeed          = "N/A"
        RAMInfo           = "N/A"
        RAMModuleSummary  = "N/A"
        RAMModules        = @()
        RAMTiming         = "N/A"
        RAMTimingNote     = "SPD časování není dostupné (vyžaduje přístup k SPD)"
        RAMVoltage        = "N/A"
        GPUName           = "N/A"
        GPUVRAM           = "N/A"
        GPUIntegrated     = "N/A"
        GPUIntegratedVRAM = "N/A"
        GPULoad           = "N/A"
        GPUTemp           = "N/A"
        DPCLatency        = "N/A"
        ServicesRunning   = 0
        ServicesTotal     = 0
        Uptime            = "N/A"
        Error             = $null
    }
    
    try {
        Write-Verbose "Gathering hardware status..."
        
        # ── OS Info (Uptime, RAM) ────────────────────────────────────
        try {
            $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
            
            # Uptime
            $uptime = (Get-Date) - $os.LastBootUpTime
            $hwStatus.Uptime = "{0:dd}d {0:hh}h {0:mm}m" -f $uptime
            
            # RAM Usage
            $hwStatus.RAMTotal = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
            $ramFree = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
            $hwStatus.RAMUsed = [math]::Round($hwStatus.RAMTotal - $ramFree, 1)
            $ramPercent = [math]::Round(($hwStatus.RAMUsed / $hwStatus.RAMTotal) * 100, 0)
            $hwStatus.RAMPercent = $ramPercent
            $hwStatus.RAMPct = $ramPercent
            
            Write-Verbose "OS Info OK"
        } catch {
            Write-Verbose "OS Info failed: $($_.Exception.Message)"
        }
        
        # ── CPU Info ─────────────────────────────────────────────────
        try {
            $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
            $hwStatus.CPUName = $cpu.Name
            
            # CPU Load (multi-language support)
            try {
                $cpuCounter = $null
                $counterNames = @(
                    '\Processor(_Total)\% Processor Time',  # EN
                    '\Procesor(_Total)\% času procesoru',   # CZ
                    '\Procesor(_Total)\Czas procesora (%)', # PL
                    '\Prozessor(_Total)\Prozessorzeit (%)', # DE
                    '\Procesor(_Total)\% času procesora'    # SK
                )
                
                foreach ($counterName in $counterNames) {
                    try {
                        $cpuCounter = Get-Counter $counterName -ErrorAction Stop
                        break
                    } catch { }
                }
                
                if ($null -ne $cpuCounter) {
                    $hwStatus.CPULoad = [math]::Round($cpuCounter.CounterSamples[0].CookedValue, 1)
                }
            } catch {
                Write-Verbose "CPU Load counter failed: $($_.Exception.Message)"
            }
            
            Write-Verbose "CPU Info OK"
        } catch {
            Write-Verbose "CPU Info failed: $($_.Exception.Message)"
        }
        
        # ── GPU Info ─────────────────────────────────────────────────
        try {
            $videoControllersRaw = Get-CimInstance Win32_VideoController -ErrorAction Stop
            $videoControllers = @()
            if ($videoControllersRaw) {
                $videoControllers = $videoControllersRaw | Where-Object {
                    $null -ne $_.Name -and $_.Name -notmatch 'Remote|VNC|Basic Display'
                }
            }

            $primaryGpu = $null
            if ($videoControllers.Count -gt 0) {
                $primaryGpu = $videoControllers |
                    Sort-Object -Property @{ Expression = { if ($_.AdapterRAM) { [int64]$_.AdapterRAM } else { 0 } } ; Descending = $true } |
                    Select-Object -First 1
            }

            if ($null -eq $primaryGpu -and $videoControllersRaw) {
                $primaryGpu = $videoControllersRaw | Select-Object -First 1
            }

            if ($null -ne $primaryGpu) {
                $hwStatus.GPUName = $primaryGpu.Name
                if ($primaryGpu.AdapterRAM -and $primaryGpu.AdapterRAM -gt 0) {
                    $hwStatus.GPUVRAM = ("{0:N1} GB" -f ($primaryGpu.AdapterRAM / 1GB))
                }
            }

            $igpuPatterns = '(?i)intel|iris|uhd|xe graphics|hd graphics|radeon\(tm\) graphics|vega graphics'
            $igpuCandidate = $null
            if ($videoControllers.Count -gt 0) {
                $igpuCandidate = $videoControllers |
                    Where-Object {
                        $_.Name -match $igpuPatterns -or ($_.VideoProcessor -and $_.VideoProcessor -match $igpuPatterns) -or ($_.PNPDeviceID -and $_.PNPDeviceID -match 'VEN_8086')
                    } |
                    Sort-Object -Property @{ Expression = { if ($_.AdapterRAM) { [int64]$_.AdapterRAM } else { 0 } } ; Descending = $true } |
                    Select-Object -First 1
            }

            if ($igpuCandidate) {
                $sameDevice = $false
                if ($primaryGpu) {
                    if ($primaryGpu.PNPDeviceID -and $igpuCandidate.PNPDeviceID -and ($primaryGpu.PNPDeviceID -eq $igpuCandidate.PNPDeviceID)) {
                        $sameDevice = $true
                    } elseif ($primaryGpu.DeviceID -and $igpuCandidate.DeviceID -and ($primaryGpu.DeviceID -eq $igpuCandidate.DeviceID)) {
                        $sameDevice = $true
                    }
                }

                if (-not $sameDevice) {
                    $hwStatus.GPUIntegrated = $igpuCandidate.Name
                    if ($igpuCandidate.AdapterRAM -and $igpuCandidate.AdapterRAM -gt 0) {
                        $hwStatus.GPUIntegratedVRAM = ("{0:N1} GB" -f ($igpuCandidate.AdapterRAM / 1GB))
                    }
                }
                elseif ($null -eq $primaryGpu) {
                    $hwStatus.GPUName = $igpuCandidate.Name
                }
            }

            Write-Verbose "GPU Info OK"
        } catch {
            Write-Verbose "GPU Info failed: $($_.Exception.Message)"
        }
        
        # ── RAM Info (Type, Speed, XMP) ──────────────────────────────
        try {
            $ramModules = Get-CimInstance Win32_PhysicalMemory -ErrorAction Stop
            
            if ($ramModules) {
                $hwStatus.RAMModules = $ramModules
                $moduleSummaries = @()
                foreach ($module in $ramModules) {
                    $capacityGb = if ($module.Capacity) { [math]::Round(($module.Capacity / 1GB), 1) } else { 0 }
                    $manufacturer = if ($module.Manufacturer) { $module.Manufacturer.Trim() } else { "Unknown" }
                    $partNumber = if ($module.PartNumber) { $module.PartNumber.Trim() } else { "N/A" }
                    if ($capacityGb -gt 0) {
                        $moduleSummaries += ("{0} GB {1} {2}" -f $capacityGb, $manufacturer, $partNumber).Trim()
                    }
                    elseif ($capacityGb -eq 0 -and $partNumber -ne "N/A") {
                        $moduleSummaries += ("{0} {1}" -f $manufacturer, $partNumber).Trim()
                    }
                }
                if ($moduleSummaries.Count -gt 0) {
                    $hwStatus.RAMModuleSummary = ($moduleSummaries -join '; ')
                }

                $firstModule = $ramModules | Select-Object -First 1
                
                # RAM Type (DDR3/DDR4/DDR5)
                $ramTypeCode = $firstModule.SMBIOSMemoryType
                $ramTypeName = switch ($ramTypeCode) {
                    20 { "DDR" }
                    21 { "DDR2" }
                    24 { "DDR3" }
                    26 { "DDR4" }
                    34 { "DDR5" }
                    default { "Unknown" }
                }
                $hwStatus.RAMType = $ramTypeName

                if ($firstModule.ConfiguredVoltage -and $firstModule.ConfiguredVoltage -gt 0) {
                    $hwStatus.RAMVoltage = ("{0:N3} V" -f ($firstModule.ConfiguredVoltage / 1000))
                }
                elseif ($firstModule.MinVoltage -and $firstModule.MinVoltage -gt 0) {
                    $hwStatus.RAMVoltage = ("{0:N3} V" -f ($firstModule.MinVoltage / 1000))
                }

                # RAM Speed with XMP Detection (1:1 from v1.ps1)
                $speed = $firstModule.ConfiguredClockSpeed
                if ($null -ne $speed -and $speed -gt 0) {
                    # XMP STATUS DETECTION
                    $xmpStatus = ""
                    
                    if ($ramTypeCode -eq 26) {  # DDR4
                        $jedecDDR4 = @(1866, 2133, 2400, 2666, 2933, 3200)
                        if ($speed -in $jedecDDR4) {
                            $xmpStatus = " | [X] JEDEC"
                        } elseif ($speed -gt 2133) {
                            $xmpStatus = " | [OK] XMP"
                        } else {
                            $xmpStatus = " | [?]"
                        }
                    }
                    elseif ($ramTypeCode -eq 34) {  # DDR5
                        $jedecDDR5 = @(4800, 5200, 5600)
                        if ($speed -in $jedecDDR5) {
                            if ($speed -eq 4800) {
                                $xmpStatus = " | [?] 4800"
                            } else {
                                $xmpStatus = " | [?] JEDEC"
                            }
                        } elseif ($speed -gt 5600) {
                            $xmpStatus = " | [OK] XMP"
                        } else {
                            $xmpStatus = " | [?]"
                        }
                    }
                    elseif ($ramTypeCode -eq 24) {  # DDR3
                        if ($speed -gt 1600) {
                            $xmpStatus = " | [OK] XMP"
                        }
                    }
                    
                    # Format: DDR5-6000 MT/s | [OK] XMP
                    $ramSpeedInfo = "$ramTypeName-$speed MT/s$xmpStatus"
                    $hwStatus.RAMSpeed = $ramSpeedInfo
                    $hwStatus.RAMInfo = $ramSpeedInfo

                    # Calculate base clock / theoretical cycle time (DDR is double data rate)
                    $baseClockMHz = [math]::Round(($speed / 2), 1)
                    if ($baseClockMHz -gt 0) {
                        $cycleNs = [math]::Round((1000 / $baseClockMHz), 3)
                        $hwStatus.RAMTiming = "tCK {0} ns (Base clock {1} MHz)" -f $cycleNs, $baseClockMHz
                        $hwStatus.RAMTimingNote = "CAS / tRCD / tRP nejsou vystaveny přes SMBIOS; vyžadován SPD přístup"
                    }
                }
                else {
                    # Fallback to Speed property if ConfiguredClockSpeed not available
                    if ($firstModule.Speed) {
                        $ramSpeedInfo = "$($firstModule.Speed) MHz"
                        $hwStatus.RAMSpeed = $ramSpeedInfo
                        $hwStatus.RAMInfo = $ramSpeedInfo
                    }
                }
            }
            
            Write-Verbose "RAM Info OK (with XMP detection)"
        } catch {
            Write-Verbose "RAM Info failed: $($_.Exception.Message)"
        }
        
        # ── DPC Latency ──────────────────────────────────────────────
        try {
            $dpcCounter = $null
            $counterNames = @(
                '\Processor(_Total)\% DPC Time',           # EN
                '\Procesor(_Total)\% času DPC',            # CZ
                '\Procesor(_Total)\Czas DPC (%)',          # PL
                '\Prozessor(_Total)\DPC-Zeit (%)',         # DE
                '\Procesor(_Total)\% času DPC'             # SK
            )
            
            foreach ($counterName in $counterNames) {
                try {
                    $dpcCounter = Get-Counter $counterName -ErrorAction Stop
                    break
                } catch { }
            }
            
            if ($null -ne $dpcCounter) {
                $dpcValue = $dpcCounter.CounterSamples[0].CookedValue * 10
                $hwStatus.DPCLatency = [math]::Round($dpcValue, 1)
            }
            
            Write-Verbose "DPC Latency OK"
        } catch {
            Write-Verbose "DPC Latency failed: $($_.Exception.Message)"
        }

        # ── Services Summary ──────────────────────────────────────────
        try {
            $serviceData = Get-Service -ErrorAction Stop
            if ($serviceData) {
                $hwStatus.ServicesTotal = $serviceData.Count
                $hwStatus.ServicesRunning = ($serviceData | Where-Object { $_.Status -eq 'Running' }).Count
            }
        } catch {
            Write-Verbose "Service enumeration failed: $($_.Exception.Message)"
        }
        
        Write-CoreLog "Hardware status gathered successfully" -Level SUCCESS
        
    } catch {
        $hwStatus.Error = $_.Exception.Message
        Write-CoreLog "Hardware status gathering failed: $($hwStatus.Error)" -Level ERROR
        Write-Error "Hardware status gathering failed: $($hwStatus.Error)"
    }
    
    return $hwStatus
}

function Show-HWHeader {
    <#
    .SYNOPSIS
        Zobrazí statický HW snapshot (CPU/RAM/GPU/XMP/DPC/Uptime).
    
    .DESCRIPTION
        Načte HW status pomocí Get-HWStatus a zobrazí formatovaný header.
        Optimalizováno pro rychlost - jeden snapshot, žádné live updaty.
    
    .PARAMETER Interval
        Ignorováno (zachováno pro zpětnou kompatibilitu).
    
    .EXAMPLE
        Show-HWHeader
        
        # OUTPUT:
        # ═══════════════════════════════════════════════════════════════
        # 💻 CPU: Intel i9-13900K | Load: 12% | RAM: 16/32 GB (50%)
        # 🎮 GPU: RTX 4090
        # 💾 RAM: DDR5 @ 6000 MHz | ⏱️ Uptime: 2d 15h 32m
        # ═══════════════════════════════════════════════════════════════
    
    .NOTES
        - Uses Get-HWStatus for data retrieval
        - Displays formatted output with colors
        - Includes network adapter info
    #>
    [CmdletBinding()]
    param (
        [int]$Interval = 1000  # Ignored, kept for compatibility
    )
    
    try {
        Write-Verbose "Displaying HW header..."
        
        # Načíst HW status
        $hw = Get-HWStatus
        
        if ($hw.Error) {
            Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Red
            Write-Host "[!] Chyba při načítání HW informací: $($hw.Error)" -ForegroundColor Red
            Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Red
            return
        }
        
        # Formátovat výstup
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        
        # CPU + RAM řádek
        $cpuLine = "💻 CPU: {0} | Load: {1}% | RAM: {2}/{3} GB ({4}%)" -f `
            $hw.CPUName, $hw.CPULoad, $hw.RAMUsed, $hw.RAMTotal, $hw.RAMPercent
        Write-Host $cpuLine -ForegroundColor White
        
        # GPU řádek
        $gpuLine = "🎮 GPU: {0}" -f $hw.GPUName
        Write-Host $gpuLine -ForegroundColor White
        if ($hw.GPUVRAM -and $hw.GPUVRAM -ne 'N/A') {
            Write-Host ("   ↳ VRAM: {0}" -f $hw.GPUVRAM) -ForegroundColor Gray
        }
        if ($hw.GPUIntegrated -and $hw.GPUIntegrated -ne 'N/A' -and $hw.GPUIntegrated -ne $hw.GPUName) {
            Write-Host ("🖼️ iGPU: {0}" -f $hw.GPUIntegrated) -ForegroundColor White
            if ($hw.GPUIntegratedVRAM -and $hw.GPUIntegratedVRAM -ne 'N/A') {
                Write-Host ("   ↳ iGPU VRAM: {0}" -f $hw.GPUIntegratedVRAM) -ForegroundColor Gray
            }
        }
        
        # RAM info + Uptime řádek (RAMSpeed už obsahuje Type-Speed MT/s | XMP status)
        $infoLine = "💾 RAM: {0} | ⏱️ Uptime: {1}" -f `
            $hw.RAMSpeed, $hw.Uptime
        Write-Host $infoLine -ForegroundColor Gray
        
        # Network adapter info (pokud je dostupné)
        try {
            $netInfo = Get-ActiveNetworkInfo
            if ($netInfo -and $netInfo.Count -gt 0) {
                foreach ($netLine in $netInfo) {
                    Write-Host "🌐 $netLine" -ForegroundColor DarkCyan
                }
            }
        } catch {
            Write-Verbose "Network info skipped: $($_.Exception.Message)"
        }
        
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        
        Write-CoreLog "HW Header displayed" -Level INFO
        
    } catch {
        Write-CoreLog "HW Header display failed: $($_.Exception.Message)" -Level ERROR
        Write-Error "HW Header display failed: $($_.Exception.Message)"
    }
}

function Write-HWHeader {
    <#
    .SYNOPSIS
        Alias pro Show-HWHeader (zpětná kompatibilita).
    
    .DESCRIPTION
        Proxy funkce pro Show-HWHeader.
    
    .EXAMPLE
        Write-HWHeader
    #>
    [CmdletBinding()]
    param (
        [int]$Interval = 1000
    )
    
    Show-HWHeader -Interval $Interval
}

# ───────────────────────────────────────────────────────────────────────────
# CPU INFORMATION
# ───────────────────────────────────────────────────────────────────────────

function Get-CPUInfo {
    <#
    .SYNOPSIS
        Získá detailní informace o CPU.
    
    .DESCRIPTION
        Vrací kompletní informace o procesoru včetně počtu jader, cache, virtualizace.
        Optimalizováno pro rychlost pomocí CIM.
    
    .OUTPUTS
        [PSCustomObject] s vlastnostmi:
        - Name, Manufacturer
        - PhysicalCores, LogicalProcessors
        - MaxClockSpeed, CurrentClockSpeed
        - L2CacheSize, L3CacheSize
        - VirtualizationEnabled, HyperThreadingEnabled
        - Architecture (x86/x64/ARM)
    
    .EXAMPLE
        $cpu = Get-CPUInfo
        Write-Host "CPU: $($cpu.Name)"
        Write-Host "Cores: $($cpu.PhysicalCores) / Threads: $($cpu.LogicalProcessors)"
        Write-Host "HT: $($cpu.HyperThreadingEnabled)"
    
    .NOTES
        - Uses Get-CimInstance Win32_Processor
        - Detects HyperThreading (LogicalProcessors > PhysicalCores)
        - Cache sizes in KB
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    $cpuInfo = [PSCustomObject]@{
        Name                    = "N/A"
        Manufacturer            = "N/A"
        PhysicalCores           = 0
        LogicalProcessors       = 0
        MaxClockSpeed           = 0
        CurrentClockSpeed       = 0
        L2CacheSize             = 0
        L3CacheSize             = 0
        VirtualizationEnabled   = $false
        HyperThreadingEnabled   = $false
        Architecture            = "Unknown"
        Error                   = $null
    }
    
    try {
        Write-Verbose "Gathering CPU information..."
        
        $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
        
        if ($null -eq $cpu) {
            throw "Failed to retrieve CPU information"
        }
        
        # Basic info
        $cpuInfo.Name = $cpu.Name
        $cpuInfo.Manufacturer = $cpu.Manufacturer
        $cpuInfo.PhysicalCores = $cpu.NumberOfCores
        $cpuInfo.LogicalProcessors = $cpu.NumberOfLogicalProcessors
        $cpuInfo.MaxClockSpeed = $cpu.MaxClockSpeed
        $cpuInfo.CurrentClockSpeed = $cpu.CurrentClockSpeed
        
        # Cache sizes (convert to KB if needed)
        if ($cpu.L2CacheSize) {
            $cpuInfo.L2CacheSize = $cpu.L2CacheSize
        }
        if ($cpu.L3CacheSize) {
            $cpuInfo.L3CacheSize = $cpu.L3CacheSize
        }
        
        # Virtualization
        if ($null -ne $cpu.VirtualizationFirmwareEnabled) {
            $cpuInfo.VirtualizationEnabled = $cpu.VirtualizationFirmwareEnabled
        }
        
        # HyperThreading detection
        if ($cpuInfo.LogicalProcessors -gt $cpuInfo.PhysicalCores) {
            $cpuInfo.HyperThreadingEnabled = $true
        }
        
        # Architecture
        $cpuInfo.Architecture = switch ($cpu.Architecture) {
            0  { "x86" }
            9  { "x64" }
            12 { "ARM64" }
            default { "Unknown ($($cpu.Architecture))" }
        }
        
        Write-CoreLog "CPU info retrieved: $($cpuInfo.Name)" -Level SUCCESS
        Write-Verbose "CPU: $($cpuInfo.PhysicalCores)C/$($cpuInfo.LogicalProcessors)T @ $($cpuInfo.MaxClockSpeed) MHz"
        
    } catch {
        $cpuInfo.Error = $_.Exception.Message
        Write-CoreLog "CPU info retrieval failed: $($cpuInfo.Error)" -Level ERROR
        Write-Error "Failed to get CPU info: $($cpuInfo.Error)"
    }
    
    return $cpuInfo
}

function Show-CPUTopology {
    <#
    .SYNOPSIS
        Zobrazí CPU topologii a detaily.
    
    .DESCRIPTION
        Formátovaný výstup CPU informací včetně jader, cache, virtualizace.
        Detekuje P-cores/E-cores pro Intel 12+ generaci (Alder Lake+).
    
    .EXAMPLE
        Show-CPUTopology
        
        # OUTPUT:
        # ═══════════════════════════════════════
        # CPU TOPOLOGY
        # ═══════════════════════════════════════
        # Processor: Intel i9-13900K
        # Cores: 24 (8P + 16E) | Threads: 32
        # Clock: 3.0 GHz (Max: 5.8 GHz)
        # Cache: L2=32 MB | L3=36 MB
        # Virtualization: Enabled
        # HyperThreading: Enabled
        # ═══════════════════════════════════════
    
    .NOTES
        - Calls Get-CPUInfo for data
        - Formatted colored output
        - Detects hybrid architecture (P+E cores)
    #>
    [CmdletBinding()]
    param()
    
    try {
        Write-Verbose "Displaying CPU topology..."
        
        $cpu = Get-CPUInfo
        
        if ($cpu.Error) {
            Write-Host "═══════════════════════════════════════" -ForegroundColor Red
            Write-Host "[!] Chyba při načítání CPU informací: $($cpu.Error)" -ForegroundColor Red
            Write-Host "═══════════════════════════════════════" -ForegroundColor Red
            return
        }
        
        # Header
        Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "CPU TOPOLOGY" -ForegroundColor White
        Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
        
        # Processor name
        Write-Host "Processor: $($cpu.Name)" -ForegroundColor White
        
        # Cores/Threads (detect hybrid architecture)
        $coreInfo = "$($cpu.PhysicalCores) Cores | $($cpu.LogicalProcessors) Threads"
        
        # Intel 12+ gen detection (simplified heuristic)
        if ($cpu.Name -match "i[3579]-1[2-9]\d{3}[KF]?") {
            # Estimate P/E cores (rough approximation)
            $pCores = [math]::Floor($cpu.PhysicalCores / 3)
            $eCores = $cpu.PhysicalCores - $pCores
            $coreInfo = "$($cpu.PhysicalCores) ($($pCores)P + $($eCores)E) | $($cpu.LogicalProcessors) Threads"
        }
        
        Write-Host "Cores: $coreInfo" -ForegroundColor White
        
        # Clock speeds
        $currentGHz = [math]::Round($cpu.CurrentClockSpeed / 1000, 1)
        $maxGHz = [math]::Round($cpu.MaxClockSpeed / 1000, 1)
        Write-Host "Clock: $currentGHz GHz (Max: $maxGHz GHz)" -ForegroundColor Gray
        
        # Cache
        $l2MB = [math]::Round($cpu.L2CacheSize / 1024, 1)
        $l3MB = [math]::Round($cpu.L3CacheSize / 1024, 1)
        Write-Host "Cache: L2=$l2MB MB | L3=$l3MB MB" -ForegroundColor Gray
        
        # Features
        $vtStatus = if ($cpu.VirtualizationEnabled) { "Enabled" } else { "Disabled" }
        $htStatus = if ($cpu.HyperThreadingEnabled) { "Enabled" } else { "Disabled" }
        
        Write-Host "Virtualization: $vtStatus" -ForegroundColor $(if ($cpu.VirtualizationEnabled) { "Green" } else { "Yellow" })
        Write-Host "HyperThreading: $htStatus" -ForegroundColor $(if ($cpu.HyperThreadingEnabled) { "Green" } else { "Yellow" })
        
        # Architecture
        Write-Host "Architecture: $($cpu.Architecture)" -ForegroundColor Gray
        
        # Footer
        Write-Host "═══════════════════════════════════════" -ForegroundColor Cyan
        
        Write-CoreLog "CPU Topology displayed" -Level INFO
        
    } catch {
        Write-CoreLog "CPU Topology display failed: $($_.Exception.Message)" -Level ERROR
        Write-Error "CPU Topology display failed: $($_.Exception.Message)"
    }
}


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# NOTE: Backup utilities moved to Utils.psm1
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
#  Functions now available via Utils.psm1 import:
#  - Get-BackupData
#  - Save-BackupData
#  - Get-AllTweakableItems
#  - Backup-RegistryValue
#  - Backup-ServiceState
#  - Restore-RegistryValue
#  - Wait-ScriptContinue
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•


Export-ModuleMember -Function @(
    # Diagnostic Menu Functions
    'Show-DiagnosticsMenu',
    'Show-DiagHeader',
    'Test-DiagnosticsIntegrity',
    
    # Static Diagnostic Functions
    'Show-StaticDiagnostics',
    'Show-SystemLogs',
    'Show-LastBSOD',
    
    # Dump Analysis Functions
    'Show-DumpAnalyzer',
    'Show-SmartDumpSummary',
    'Show-BSODDumpMode',
    
    # Dump Operations Functions
    'Clear-Dumps',
    'Export-SystemLogs',
    'Copy-DumpsToDesktop',
    
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # UTILITY FUNCTIONS (merged from Utils.psm1)
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    
    # Network Utilities
    'Get-ActiveNetworkInfo',
    
    # Hardware Status
    'Get-HWStatus',
    'Show-HWHeader',
    'Write-HWHeader',
    
    # CPU Information
    'Get-CPUInfo',
    'Show-CPUTopology',

    # Module Entry
    'Invoke-ModuleEntry'
    
    # NOTE: Backup utilities (Get-BackupData, Save-BackupData, Get-AllTweakableItems,
    #       Backup-RegistryValue, Backup-ServiceState, Restore-RegistryValue,
    #       Wait-ScriptContinue) are now exported by Utils.psm1
)
