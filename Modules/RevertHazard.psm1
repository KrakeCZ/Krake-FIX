# ═══════════════════════════════════════════════════════════════════════════
# Module: RevertHazard.psm1
# ═══════════════════════════════════════════════════════════════════════════
# Project:      KRAKE-FIX v2 Modular
# Version:      2.0.0
# Author:       KRAKE-FIX Team
# Created:      2025-10-29
# Last Updated: 2025-10-29
# ═══════════════════════════════════════════════════════════════════════════
# Description:  [6] Obnovit bezpečné výchozí nastavení Windows
#               - Restore security tweaks (CPU mitigations, VBS, HVCI, etc.)
#               - Restore performance tweaks (Win32Prio, HID, GPU)
#               - Restore Windows Update settings
#               - Restore Defender & Telemetry services
# Category:     System Restore / Recovery
# Dependencies: Core.psm1 (Invoke-RevertToDefaults)
# Admin Rights: Required
# ═══════════════════════════════════════════════════════════════════════════
# ⚠️  SECURITY & COMPLIANCE NOTICE
# ═══════════════════════════════════════════════════════════════════════════
# • This module restores system security and performance settings to defaults.
# • Designed for educational and testing purposes only.
# • Author assumes no liability for misuse outside academic context.
# • RESTART REQUIRED after restoring security settings!
# ═══════════════════════════════════════════════════════════════════════════
# ⚠️ Tento modul může měnit systémové nastavení.
# Používej pouze ve studijním / testovacím prostředí.
# Autor neručí za zneužití mimo akademické účely.
# ===========================================================
#Requires -Version 5.1
#Requires -RunAsAdministrator
# ───────────────────────────────────────────────────────────────────────────
# IMPORT CORE MODULE
# ───────────────────────────────────────────────────────────────────────────
# Use Core module functions - loaded by Main.ps1, only import if standalone
if (-not (Get-Command Write-CoreLog -ErrorAction SilentlyContinue)) {
    $CoreModule = Join-Path $PSScriptRoot 'Core.psm1'
    if (Test-Path $CoreModule) {
        Import-Module $CoreModule -Force -ErrorAction Stop
    }
    else {
        Write-Error "CRITICAL: Core.psm1 not found! RevertHazard.psm1 requires Core.psm1."
        throw "Missing dependency: Core.psm1"
    }
}
# ───────────────────────────────────────────────────────────────────────────
# MODULE INITIALIZATION
# ───────────────────────────────────────────────────────────────────────────
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ModuleName = 'RevertHazard'
$script:ModuleVersion = '2.0.0'
$script:LogPath = Join-Path $env:TEMP "KRAKE-FIX-$script:ModuleName.log"
# ═══════════════════════════════════════════════════════════════════════════
# REVERT MENU - MAIN FUNCTION
# ═══════════════════════════════════════════════════════════════════════════
function Show-RevertMenu {
    <#
    .SYNOPSIS
        [6] Menu pro obnovu změn - Restore system to safe defaults.
    .DESCRIPTION
        Interactive menu pro obnovení systémových nastavení na bezpečné výchozí hodnoty:
        Zrcadlí strukturu Security modulu, ale provádí OBNOVU místo aplikace tweaků.
    .NOTES
        Volá Invoke-RevertToDefaults s různými kategoriemi.
        ⚠️ Některé kategorie vyžadují RESTART systému!
    #>
    [CmdletBinding()]
    param()
    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Yellow
        Write-Host "           MENU PRO OBNOVU ZMĚN                   " -ForegroundColor Yellow
        Write-Host "==================================================" -ForegroundColor Yellow
        Write-Host "Vyberte, kterou kategorii chcete obnovit:"
        Write-Host ""
        Write-Host "BEZPEČNOSTNÍ TWEAKY:" -ForegroundColor Cyan
        Write-Host "--------------------------------------------------"
        Write-Host "[1]   Mitigace CPU Intel (Spectre/Meltdown)"
        Write-Host "[2.1] Windows Update služby (blokace služeb)" -ForegroundColor Gray
        Write-Host "[2.2] Windows Update ovladače (blokace přes registry)" -ForegroundColor Gray
        Write-Host "[3]   VBS & Hyper-V (Virtualization)"
        Write-Host "[4]   Integrita Jádra (Core Isolation & HVCI)"
        Write-Host "[5]   LSA Ochrana Intel (Local Security Authority)"
        Write-Host "[6]   TSX Instrukce Intel"
        Write-Host "[7.1] MS Defender (Real-time ochrana)" -ForegroundColor Red
        Write-Host "[7.2] MS Defender (Blokace - Registry+Služby)" -ForegroundColor Red
        Write-Host "[8]   'Full Admin Control' kontext Menu"
        Write-Host "[9]   Doplňkové bezpečnostní služby (VSS, atd.)"
        Write-Host "[10]  Telemetrické služby" -ForegroundColor Red
        Write-Host "[11]  HOSTS Telemetry (obnovit HOSTS file)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "VÝKONNOSTNÍ TWEAKY:" -ForegroundColor Magenta
        Write-Host "--------------------------------------------------"
        Write-Host "[20] Win32PrioritySeparation (na výchozí hodnotu)"
        Write-Host "[21] Latence Vstupu (Klávesnice/Myš)"
        Write-Host "[22] NVIDIA GPU Tweaks"
        Write-Host "[23] Intel iGPU Tweaks"
        Write-Host ""
        Write-Host "KOMPLETNÍ OBNOVA:" -ForegroundColor Cyan
        Write-Host "--------------------------------------------------"
        Write-Host "[ALL-SEC]  Obnovit VŠECHNY bezpečnostní tweaky (1-11)" -ForegroundColor Yellow
        Write-Host "[ALL-PERF] Obnovit VŠECHNY výkonnostní tweaky (20-23)" -ForegroundColor Magenta
        Write-Host "[ALL]      Obnovit VŠECHNY tweaky (bezpečnostní + výkonnostní)" -ForegroundColor Red
        Write-Host "--------------------------------------------------"
        Write-Host "[Q] Zpět do hlavního menu" -ForegroundColor White
        Write-Host ""
        $choice = Read-Host -Prompt "Zadejte svou volbu"
        switch ($choice) {
            '1' { Invoke-RevertToDefaults -Category MitigationsCPU }
            '2.1' { 
                Write-Host ""
                Write-Host "Obnovuji Windows Update služby..." -ForegroundColor Gray
                Invoke-RevertToDefaults -Category WinUpdateServices
            }
            '2.2' { 
                Write-Host ""
                Write-Host "Obnovuji Windows Update ovladače (registry)..." -ForegroundColor Gray
                Invoke-RevertToDefaults -Category WinUpdateDrivers
            }
            '3' { Invoke-RevertToDefaults -Category VBS }
            '4' { Invoke-RevertToDefaults -Category Integrity }
            '5' { Invoke-RevertToDefaults -Category LSA }
            '6' { Invoke-RevertToDefaults -Category TSX }
            '7.1' { Invoke-RevertToDefaults -Category DefenderRT }
            '7.2' { Invoke-RevertToDefaults -Category DefenderBlock }
            '8' { Invoke-RevertToDefaults -Category FullAdmin }
            '9' { Invoke-RevertToDefaults -Category OtherServices }
            '10' { Invoke-RevertToDefaults -Category TelemetryServices }
            '11' { 
                Write-Host ""
                Write-Host "Spouštím HOSTS TELEMETRY RESTORE..." -ForegroundColor Yellow
                Invoke-HostsTelemetryRestore
            }
            '20' { Invoke-RevertToDefaults -Category Win32Prio }
            '21' { Invoke-RevertToDefaults -Category HIDLatency }
            '22' { Invoke-RevertToDefaults -Category NvidiaGPU }
            '23' { Invoke-RevertToDefaults -Category IntelGPU }
            'ALL-SEC' { 
                Write-Host ""
                Write-Host "Obnovuji VŠECHNY bezpečnostní tweaky..." -ForegroundColor Yellow
                Invoke-RevertToDefaults -Category MitigationsCPU
                Write-Host "Obnovuji Windows Update služby..." -ForegroundColor Gray
                Invoke-RevertToDefaults -Category WinUpdateServices
                Write-Host "Obnovuji Windows Update ovladače (registry)..." -ForegroundColor Gray
                Invoke-RevertToDefaults -Category WinUpdateDrivers
                Invoke-RevertToDefaults -Category VBS
                Invoke-RevertToDefaults -Category Integrity
                Invoke-RevertToDefaults -Category LSA
                Invoke-RevertToDefaults -Category TSX
                Invoke-RevertToDefaults -Category DefenderRT
                Invoke-RevertToDefaults -Category DefenderBlock
                Invoke-RevertToDefaults -Category FullAdmin
                Invoke-RevertToDefaults -Category OtherServices
                Invoke-RevertToDefaults -Category TelemetryServices
                Invoke-HostsTelemetryRestore
            }
            'ALL-PERF' { 
                Write-Host ""
                Write-Host "Obnovuji VŠECHNY výkonnostní tweaky..." -ForegroundColor Magenta
                Invoke-RevertToDefaults -Category Win32Prio
                Invoke-RevertToDefaults -Category HIDLatency
                Invoke-RevertToDefaults -Category NvidiaGPU
                Invoke-RevertToDefaults -Category IntelGPU
            }
            'ALL' { 
                Write-Host ""
                Write-Host "Obnovuji VŠECHNY tweaky (bezpečnostní + výkonnostní)..." -ForegroundColor Red
                Invoke-RevertToDefaults -Category MitigationsCPU
                Write-Host "Obnovuji Windows Update služby..." -ForegroundColor Gray
                Invoke-RevertToDefaults -Category WinUpdateServices
                Write-Host "Obnovuji Windows Update ovladače (registry)..." -ForegroundColor Gray
                Invoke-RevertToDefaults -Category WinUpdateDrivers
                Invoke-RevertToDefaults -Category VBS
                Invoke-RevertToDefaults -Category Integrity
                Invoke-RevertToDefaults -Category LSA
                Invoke-RevertToDefaults -Category TSX
                Invoke-RevertToDefaults -Category DefenderRT
                Invoke-RevertToDefaults -Category DefenderBlock
                Invoke-RevertToDefaults -Category FullAdmin
                Invoke-RevertToDefaults -Category OtherServices
                Invoke-RevertToDefaults -Category TelemetryServices
                Invoke-HostsTelemetryRestore
                Invoke-RevertToDefaults -Category Win32Prio
                Invoke-RevertToDefaults -Category HIDLatency
                Invoke-RevertToDefaults -Category NvidiaGPU
                Invoke-RevertToDefaults -Category IntelGPU
            }
            'Q' { return }
            default { Write-Warning "Neplatná volba." ; Start-Sleep -Seconds 2 }
        }
        if ($choice -ne 'Q') { 
            Write-Host "Operace dokončena. Stiskněte klávesu pro pokračování..." 
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown") 
        }
    }
}
# ═══════════════════════════════════════════════════════════════════════════
# REVERT TO DEFAULTS - CORE FUNCTION
# ═══════════════════════════════════════════════════════════════════════════
function Invoke-RevertToDefaults {
    <#
    .SYNOPSIS
        Obnoví systémové nastavení pro zvolenou kategorii na bezpečné výchozí hodnoty.
    .PARAMETER Category
        Kategorie pro obnovu (např. MitigationsCPU, VBS, Defender, atd.)
    .PARAMETER Apply
        Interní switch - pokud je $true, aplikuje tweak místo obnovy.
        (Používá se pro zrcadlení Security modulu)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Category,
        
        [switch] $Apply
    )
    # Potvrzení pro bezpečnostní kategorie (kromě výkonnostních)
    if (!$Apply) {
        if ($Category -notin @('Win32Prio', 'HIDLatency', 'NvidiaGPU', 'IntelGPU')) {
            $confirmation = Read-Host -Prompt "Opravdu chcete obnovit kategorii '$Category'? (Ano/Ne)"
            if ($confirmation -notmatch '^a') { 
                Write-Host "Operace zrušena." -ForegroundColor Yellow
                return 
            }
        }
    }
    $action = if ($Apply) { "Aplikuji" } else { "Obnovuji" }
    # ─────────────────────────────────────────────────────────────────────────
    # KATEGORIE: MitigationsCPU
    # ─────────────────────────────────────────────────────────────────────────
    if ($Category -in @('MitigationsCPU', 'All')) {
        Write-Host "  -> $action Mitigace CPU..." -ForegroundColor Cyan
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        # Registry operace MUSÍ běžet jako SYSTEM (HKLM:\SYSTEM\CurrentControlSet\)
        Invoke-AsSystem -ScriptBlock {
            param($Path, $IsApply)
            if ($IsApply) {
                Write-Host "  -> [SYSTEM] Aplikuji CPU mitigace..." -ForegroundColor Gray
                if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
                Remove-ItemProperty -Path $Path -Name "FeatureSettings" -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $Path -Name "FeatureSettingsOverride" -Value 3 -Type DWord -Force
                Set-ItemProperty -Path $Path -Name "FeatureSettingsOverrideMask" -Value 3 -Type DWord -Force
                Write-Host "  -> [SYSTEM] CPU mitigace aplikovány" -ForegroundColor Green
            }
            else {
                Write-Host "  -> [SYSTEM] Obnovuji CPU mitigace..." -ForegroundColor Gray
                Remove-ItemProperty -Path $Path -Name "FeatureSettingsOverride" -Force -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $Path -Name "FeatureSettingsOverrideMask" -Force -ErrorAction SilentlyContinue
                Write-Host "  -> [SYSTEM] CPU mitigace obnoveny" -ForegroundColor Green
            }
        } -ArgumentList $regPath, $Apply.IsPresent
    }
    # ─────────────────────────────────────────────────────────────────────────
    # KATEGORIE: WinUpdateServices (blokace Win Update služeb)
    # ─────────────────────────────────────────────────────────────────────────
    if ($Category -in @('WinUpdateServices', 'All')) {
        Write-Host "  -> $action Windows Update služby (blokace služeb)..." -ForegroundColor Gray
        if ($Apply) {
            Invoke-AsSystem -ScriptBlock {
                $services = @("wuauserv", "BITS", "UsoSvc", "WaaSMedicSvc", "DoSvc")
                foreach ($s in $services) { 
                    if (Get-Service $s -EA 0) { 
                        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$s" -Name Start -Value 4 -Force 
                        Stop-Service $s -Force -EA 0 
                    }
                }
            }
        }
        else {
            Invoke-AsSystem -ScriptBlock {
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv" -Name Start -Value 2 -Force; Start-Service "wuauserv" -EA 0
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\BITS" -Name Start -Value 2 -Force; Start-Service "BITS" -EA 0
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\UsoSvc" -Name Start -Value 2 -Force; Start-Service "UsoSvc" -EA 0
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" -Name Start -Value 3 -Force
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DoSvc" -Name Start -Value 2 -Force; Start-Service "DoSvc" -EA 0
            }
        }
    }
    # ─────────────────────────────────────────────────────────────────────────
    # KATEGORIE: WinUpdateDrivers (blokace ovladačů přes registry)
    # ─────────────────────────────────────────────────────────────────────────
    if ($Category -in @('WinUpdateDrivers', 'All')) {
        Write-Host "  -> $action Windows Update ovladače (blokace přes registry)..." -ForegroundColor Gray
        if ($Apply) {
            if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) { 
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null 
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Value 0 -Type DWord -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Type DWord -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -Type DWord -Force -EA 0
        }
        else {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Value 1 -Type DWord -Force -EA 0
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Force -EA 0
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Force -EA 0
        }
    }
    # ─────────────────────────────────────────────────────────────────────────
    # KATEGORIE: VBS & Hyper-V
    # ─────────────────────────────────────────────────────────────────────────
    if ($Category -in @('VBS', 'All')) {
        Write-Host "  -> $action VBS & Hyper-V..." -ForegroundColor Cyan
        # Registry operace MUSÍ běžet jako SYSTEM
        Invoke-AsSystem -ScriptBlock {
            param($IsApply)
            if ($IsApply) {
                Write-Host "  -> [SYSTEM] Vypínám VBS..." -ForegroundColor Gray
                if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard")) {
                    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 0 -Type DWord -Force -EA 0
                Write-Host "  -> [SYSTEM] VBS vypnuto (registry)" -ForegroundColor Green
            }
            else {
                Write-Host "  -> [SYSTEM] Obnovuji VBS..." -ForegroundColor Gray
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord -Force -EA 0
                Write-Host "  -> [SYSTEM] VBS obnoveno (registry)" -ForegroundColor Green
            }
        } -ArgumentList $Apply.IsPresent
        # bcdedit může běžet jako Admin
        if ($Apply) {
            bcdedit.exe /set hypervisorlaunchtype off
            Write-Host "  -> bcdedit: hypervisor launch vypnut" -ForegroundColor Green
        }
        else {
            bcdedit.exe /set hypervisorlaunchtype auto
            try { bcdedit.exe /deletevalue vm } catch {}
            Write-Host "  -> bcdedit: hypervisor launch obnoven" -ForegroundColor Green
        }
    }
    # ─────────────────────────────────────────────────────────────────────────
    # KATEGORIE: Integrity (HVCI / Memory Integrity)
    # ─────────────────────────────────────────────────────────────────────────
    if ($Category -in @('Integrity', 'All')) {
        Write-Host "  -> $action HVCI / Memory Integrity..." -ForegroundColor Cyan
        Invoke-AsSystem -ScriptBlock {
            param($IsApply)
            if ($IsApply) {
                Write-Host "  -> [SYSTEM] Vypínám HVCI..." -ForegroundColor Gray
                if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
                    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 0 -Type DWord -Force
                Write-Host "  -> [SYSTEM] HVCI vypnuto" -ForegroundColor Green
            }
            else {
                Write-Host "  -> [SYSTEM] Obnovuji HVCI..." -ForegroundColor Gray
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 1 -Type DWord -Force
                Write-Host "  -> [SYSTEM] HVCI obnoveno" -ForegroundColor Green
            }
        } -ArgumentList $Apply.IsPresent
        if ($Apply) {
            bcdedit.exe /set nointegritychecks on
            Write-Host "  -> bcdedit: integrity checks vypnuty" -ForegroundColor Green
        }
        else {
            bcdedit.exe /set nointegritychecks off
            Write-Host "  -> bcdedit: integrity checks obnoveny" -ForegroundColor Green
        }
    }
    # ─────────────────────────────────────────────────────────────────────────
    # KATEGORIE: LSA (Credential Guard)
    # ─────────────────────────────────────────────────────────────────────────
    if ($Category -in @('LSA', 'All')) {
        Write-Host "  -> $action LSA Protection / Credential Guard..." -ForegroundColor Cyan
        Invoke-AsSystem -ScriptBlock {
            param($IsApply)
            if ($IsApply) {
                Write-Host "  -> [SYSTEM] Vypínám LSA Protection..." -ForegroundColor Gray
                if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa")) {
                    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 0 -Type DWord -Force
                Write-Host "  -> [SYSTEM] LSA Protection vypnuto" -ForegroundColor Green
            }
            else {
                Write-Host "  -> [SYSTEM] Obnovuji LSA Protection..." -ForegroundColor Gray
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1 -Type DWord -Force
                Write-Host "  -> [SYSTEM] LSA Protection obnoveno" -ForegroundColor Green
            }
        } -ArgumentList $Apply.IsPresent
    }
    # ─────────────────────────────────────────────────────────────────────────
    # KATEGORIE: TSX (Intel CPU Instructions)
    # ─────────────────────────────────────────────────────────────────────────
    if ($Category -in @('TSX', 'All')) {
        Write-Host "  -> $action TSX (Intel CPU Instructions)..." -ForegroundColor Cyan
        Invoke-AsSystem -ScriptBlock {
            param($IsApply)
            if ($IsApply) {
                Write-Host "  -> [SYSTEM] Vypínám TSX..." -ForegroundColor Gray
                if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel")) {
                    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "DisableTsx" -Value 1 -Type DWord -Force
                Write-Host "  -> [SYSTEM] TSX vypnuto" -ForegroundColor Green
            }
            else {
                Write-Host "  -> [SYSTEM] Obnovuji TSX..." -ForegroundColor Gray
                Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel" -Name "DisableTsx" -Force -EA 0
                Write-Host "  -> [SYSTEM] TSX obnoveno" -ForegroundColor Green
            }
        } -ArgumentList $Apply.IsPresent
    }
    # ─────────────────────────────────────────────────────────────────────────
    # KATEGORIE: DefenderRT (Real-Time Protection)
    # ─────────────────────────────────────────────────────────────────────────
    if ($Category -in @('DefenderRT', 'All')) {
        Write-Host "  -> $action Windows Defender Real-Time Protection..." -ForegroundColor Cyan
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
        if ($Apply) {
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $regPath -Name "DisableIOAVProtection" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $regPath -Name "DisableOnAccessProtection" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $regPath -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $regPath -Name "DisableScanOnRealtimeEnable" -Value 1 -Type DWord -Force
            Write-Host "  -> Defender RT vypnut (registry)" -ForegroundColor Green
        }
        else {
            Remove-ItemProperty -Path $regPath -Name "DisableBehaviorMonitoring" -Force -EA 0
            Remove-ItemProperty -Path $regPath -Name "DisableIOAVProtection" -Force -EA 0
            Remove-ItemProperty -Path $regPath -Name "DisableOnAccessProtection" -Force -EA 0
            Remove-ItemProperty -Path $regPath -Name "DisableRealtimeMonitoring" -Force -EA 0
            Remove-ItemProperty -Path $regPath -Name "DisableScanOnRealtimeEnable" -Force -EA 0
            Write-Host "  -> Defender RT obnoven (registry)" -ForegroundColor Green
        }
    }
    # ─────────────────────────────────────────────────────────────────────────
    # KATEGORIE: DefenderBlock (Full Defender Disable)
    # ─────────────────────────────────────────────────────────────────────────
    if ($Category -in @('DefenderBlock', 'All')) {
        Write-Host "  -> $action Windows Defender (kompletní blokace)..." -ForegroundColor Cyan
        # Registry může běžet jako Admin
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
        if ($Apply) {
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force
            Write-Host "  -> Defender vypnut (registry)" -ForegroundColor Green
        }
        else {
            Remove-ItemProperty -Path $regPath -Name "DisableAntiSpyware" -Force -EA 0
            Write-Host "  -> Defender obnoven (registry)" -ForegroundColor Green
        }
        # Služba MUSÍ běžet jako SYSTEM
        Invoke-AsSystem -ScriptBlock {
            param($IsApply)
            if ($IsApply) {
                Write-Host "  -> [SYSTEM] Zastavuji WinDefend službu..." -ForegroundColor Gray
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Name Start -Value 4 -Force
                Stop-Service "WinDefend" -Force -EA 0
                Write-Host "  -> [SYSTEM] WinDefend vypnuto" -ForegroundColor Green
            }
            else {
                Write-Host "  -> [SYSTEM] Obnovuji WinDefend službu..." -ForegroundColor Gray
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Name Start -Value 2 -Force
                Start-Service "WinDefend" -EA 0
                Write-Host "  -> [SYSTEM] WinDefend obnoveno" -ForegroundColor Green
            }
        } -ArgumentList $Apply.IsPresent
    }
    # ─────────────────────────────────────────────────────────────────────────
    # KATEGORIE: FullAdmin (Enable Built-in Administrator)
    # ─────────────────────────────────────────────────────────────────────────
    if ($Category -in @('FullAdmin', 'All')) {
        Write-Host "  -> $action FullAdmin (zabudovaný správce)..." -ForegroundColor Cyan
        if ($Apply) {
            net user Administrator /active:yes
            Write-Host "  -> FullAdmin aktivován" -ForegroundColor Green
        }
        else {
            net user Administrator /active:no
            Write-Host "  -> FullAdmin deaktivován" -ForegroundColor Green
        }
    }
    # ─────────────────────────────────────────────────────────────────────────
    # KATEGORIE: OtherServices (Black Viper Barebones)
    # ─────────────────────────────────────────────────────────────────────────
    if ($Category -in @('OtherServices', 'All')) {
        Write-Host "  -> $action OtherServices (Black Viper Barebones)..." -ForegroundColor Cyan
        $barebones = @("ALG", "BFE", "BITS", "BrokerInfrastructure", "BthAvctpSvc", "CertPropSvc", 
            "COMSysApp", "CryptSvc", "DcomLaunch", "DeviceAssociationService", "Dhcp", 
            "DiagTrack", "dmwappushservice", "Dnscache", "DoSvc", "DPS", "DsmSvc", 
            "DsSvc", "EventLog", "EventSystem", "FontCache", "KeyIso", "LSM", 
            "MMCSS", "mpssvc", "NcbService", "netprofm", "NlaSvc", "nsi", 
            "PlugPlay", "Power", "ProfSvc", "RpcEptMapper", "RpcSs", "SamSs", 
            "Schedule", "SecurityHealthService", "SENS", "SgrmBroker", "ShellHWDetection", 
            "Spooler", "SSDPSRV", "StateRepository", "StorSvc", "SysMain", "SystemEventsBroker", 
            "Themes", "TokenBroker", "TrkWks", "UsoSvc", "VGAuthService", "vm3dservice", 
            "vmicguestinterface", "vmicheartbeat", "vmickvpexchange", "vmicrdv", "vmicshutdown", 
            "vmictimesync", "vmicvmsession", "vmicvss", "vmvss", "VSS", "W32Time", 
            "WaaSMedicSvc", "WdiSystemHost", "Winmgmt", "WinRM", "WpnService", "wscsvc", "wuauserv")
        Invoke-AsSystem -ScriptBlock {
            param($Services, $IsApply)
            foreach ($s in $Services) {
                if (Get-Service $s -EA 0) {
                    if ($IsApply) {
                        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$s" -Name Start -Value 2 -Force -EA 0
                    }
                    else {
                        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$s" -Name Start -Value 4 -Force -EA 0
                        Stop-Service $s -Force -EA 0
                    }
                }
            }
        } -ArgumentList $barebones, $Apply.IsPresent
        Write-Host "  -> OtherServices zpracovány" -ForegroundColor Green
    }
    # ─────────────────────────────────────────────────────────────────────────
    # KATEGORIE: TelemetryServices
    # ─────────────────────────────────────────────────────────────────────────
    if ($Category -in @('TelemetryServices', 'All')) {
        Write-Host "  -> $action Telemetry Services..." -ForegroundColor Cyan
        $telemetry = @("DiagTrack", "dmwappushservice", "WerSvc", "wercplsupport")
        Invoke-AsSystem -ScriptBlock {
            param($Services, $IsApply)
            foreach ($s in $Services) {
                if (Get-Service $s -EA 0) {
                    if ($IsApply) {
                        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$s" -Name Start -Value 4 -Force
                        Stop-Service $s -Force -EA 0
                    }
                    else {
                        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$s" -Name Start -Value 2 -Force
                        Start-Service $s -EA 0
                    }
                }
            }
        } -ArgumentList $telemetry, $Apply.IsPresent
        Write-Host "  -> Telemetry Services zpracovány" -ForegroundColor Green
    }
    # ─────────────────────────────────────────────────────────────────────────
    # KATEGORIE: HostsBlock (HOSTS file)
    # ─────────────────────────────────────────────────────────────────────────
    if ($Category -in @('HostsBlock', 'All')) {
        Write-Host "  -> $action HOSTS file (telemetry blokace)..." -ForegroundColor Cyan
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        if ($Apply) {
            $telemetryHosts = @(
                "# Telemetry Blocking",
                "0.0.0.0 vortex.data.microsoft.com",
                "0.0.0.0 vortex-win.data.microsoft.com",
                "0.0.0.0 telecommand.telemetry.microsoft.com",
                "0.0.0.0 oca.telemetry.microsoft.com",
                "0.0.0.0 watson.telemetry.microsoft.com",
                "0.0.0.0 umwatsonc.events.data.microsoft.com"
            )
            Add-Content -Path $hostsPath -Value $telemetryHosts -Force
            Write-Host "  -> HOSTS file: telemetry blokována" -ForegroundColor Green
        }
        else {
            $currentHosts = Get-Content $hostsPath -EA 0
            $cleanedHosts = $currentHosts | Where-Object { $_ -notmatch "microsoft\.com|# Telemetry" }
            Set-Content -Path $hostsPath -Value $cleanedHosts -Force
            Write-Host "  -> HOSTS file: telemetry obnoven" -ForegroundColor Green
        }
    }
    # ─────────────────────────────────────────────────────────────────────────
    # KATEGORIE: Win32Prio (Win32PrioritySeparation)
    # ─────────────────────────────────────────────────────────────────────────
    if ($Category -in @('Win32Prio', 'All')) {
        Write-Host "  -> $action Win32PrioritySeparation..." -ForegroundColor Cyan
        Invoke-AsSystem -ScriptBlock {
            param($IsApply)
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"
            if ($IsApply) {
                Write-Host "  -> [SYSTEM] Nastavuji Win32PrioritySeparation=38..." -ForegroundColor Gray
                Set-ItemProperty -Path $regPath -Name "Win32PrioritySeparation" -Value 38 -Type DWord -Force
                Write-Host "  -> [SYSTEM] Win32PrioritySeparation aplikováno" -ForegroundColor Green
            }
            else {
                Write-Host "  -> [SYSTEM] Obnovuji Win32PrioritySeparation=2..." -ForegroundColor Gray
                Set-ItemProperty -Path $regPath -Name "Win32PrioritySeparation" -Value 2 -Type DWord -Force
                Write-Host "  -> [SYSTEM] Win32PrioritySeparation obnoveno" -ForegroundColor Green
            }
        } -ArgumentList $Apply.IsPresent
    }
    # ─────────────────────────────────────────────────────────────────────────
    # KATEGORIE: HIDLatency
    # ─────────────────────────────────────────────────────────────────────────
    if ($Category -in @('HIDLatency', 'All')) {
        Write-Host "  -> $action HID Input Latency..." -ForegroundColor Cyan
        Invoke-AsSystem -ScriptBlock {
            param($IsApply)
            $kbdPath = "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters"
            $mouPath = "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"
            if ($IsApply) {
                Write-Host "  -> [SYSTEM] Nastavuji HID latency..." -ForegroundColor Gray
                Set-ItemProperty -Path $kbdPath -Name "KeyboardDataQueueSize" -Value 20 -Type DWord -Force -EA 0
                Set-ItemProperty -Path $mouPath -Name "MouseDataQueueSize" -Value 20 -Type DWord -Force -EA 0
                Write-Host "  -> [SYSTEM] HID latency aplikováno" -ForegroundColor Green
            }
            else {
                Write-Host "  -> [SYSTEM] Obnovuji HID latency..." -ForegroundColor Gray
                Remove-ItemProperty -Path $kbdPath -Name "KeyboardDataQueueSize" -Force -EA 0
                Remove-ItemProperty -Path $mouPath -Name "MouseDataQueueSize" -Force -EA 0
                Write-Host "  -> [SYSTEM] HID latency obnoveno" -ForegroundColor Green
            }
        } -ArgumentList $Apply.IsPresent
    }
    # ─────────────────────────────────────────────────────────────────────────
    # KATEGORIE: NvidiaGPU (Nvidia GPU Tweaks)
    # ─────────────────────────────────────────────────────────────────────────
    if ($Category -in @('NvidiaGPU', 'All')) {
        Write-Host "  -> $action NVIDIA GPU Tweaks..." -ForegroundColor Cyan
        if ($Apply) {
            Write-Host "  -> Obnovuji Windows výchozí NVIDIA hodnoty..." -ForegroundColor Gray
            # Windows Registry Editor Version 5.00 - Default NVIDIA values
            $nvidiaDefaults = @{
                "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" = @{
                    "EnablePreemption" = 1
                }
                "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"           = @{
                    "TdrLevel" = 3
                    "TdrDelay" = 2
                }
            }
            foreach ($regPath in $nvidiaDefaults.Keys) {
                if (Test-Path $regPath) {
                    foreach ($valueName in $nvidiaDefaults[$regPath].Keys) {
                        $defaultValue = $nvidiaDefaults[$regPath][$valueName]
                        Set-ItemProperty -Path $regPath -Name $valueName -Value $defaultValue -Type DWord -Force -EA 0
                    }
                }
            }
            Write-Host "  -> NVIDIA GPU obnoveno na výchozí hodnoty" -ForegroundColor Green
        }
        else {
            Write-Host "  -> Pro aplikaci NVIDIA tweaků použijte GPU_NVIDIA modul" -ForegroundColor Yellow
        }
    }
    # ─────────────────────────────────────────────────────────────────────────
    # KATEGORIE: IntelGPU (Intel GPU Tweaks)
    # ─────────────────────────────────────────────────────────────────────────
    if ($Category -in @('IntelGPU', 'All')) {
        Write-Host "  -> $action Intel GPU Tweaks..." -ForegroundColor Cyan
        if ($Apply) {
            Write-Host "  -> Obnovuji Windows výchozí Intel hodnoty..." -ForegroundColor Gray
            # Windows Registry Editor Version 5.00 - Default Intel values
            $intelDefaults = @{
                "ProcAmpApplyAlways"                    = 0x00000000
                "ProcAmpHue"                            = 0x00000000
                "ProcAmpSaturation"                     = 0x3f800000
                "ProcAmpContrast"                       = 0x3f800000
                "ProcAmpBrightness"                     = 0x00000000
                "EnableTCC"                             = 0x00000000
                "SatFactorRed"                          = 0x000000a0
                "SatFactorGreen"                        = 0x000000a0
                "SatFactorBlue"                         = 0x000000a0
                "SatFactorYellow"                       = 0x000000a0
                "SatFactorCyan"                         = 0x000000a0
                "SatFactorMagenta"                      = 0x000000a0
                "InputYUVRange"                         = 0x00000001
                "EnableFMD"                             = 0x00000000
                "NoiseReductionEnabledAlways"           = 0x00000000
                "NoiseReductionAutoDetectEnabledAlways" = 0x00000000
                "NoiseReductionEnableChroma"            = 0x00000000
                "NoiseReductionFactor"                  = 0x00000000
                "SharpnessEnabledAlways"                = 0x00000000
                "UISharpnessOptimalEnabledAlways"       = 0x00000000
                "SharpnessFactor"                       = 0x42300000
                "EnableSTE"                             = 0x00000001
                "SkinTone"                              = 0x00000003
                "EnableACE"                             = 0x00000001
                "EnableIS"                              = 0x00000000
                "AceLevel"                              = 0x00000005
                "EnableNLAS"                            = 0x00000000
                "NLASVerticalCrop"                      = 0x00000000
                "NLASHLinearRegion"                     = 0x3de147ae
                "NLASNonLinearCrop"                     = 0x00000000
                "GCompMode"                             = 0x00000000
                "GExpMode"                              = 0x00000000
                "InputYUVRangeApplyAlways"              = 0x00000000
                "SuperResolutionEnabled"                = 0x00000000
            }
            $intelPath = "HKLM:\SOFTWARE\Intel\Display\igfxcui\MediaKeys"
            if (Test-Path $intelPath) {
                Write-Host "  -> Nastavuji výchozí Intel MediaKeys hodnoty..." -ForegroundColor Gray
                foreach ($valueName in $intelDefaults.Keys) {
                    $defaultValue = $intelDefaults[$valueName]
                    Set-ItemProperty -Path $intelPath -Name $valueName -Value $defaultValue -Type DWord -Force -EA 0
                }
                Write-Host "  -> Intel GPU obnoveno na výchozí hodnoty" -ForegroundColor Green
            }
            else {
                Write-Host "  -> Intel GPU registry cesta nenalezena (není Intel GPU?)" -ForegroundColor Yellow
            }
        }
        else {
            Write-Host "  -> Pro aplikaci Intel tweaků použijte GPU_Intel modul" -ForegroundColor Yellow
        }
    }
    Write-Host "`n  -> Operace dokončena." -ForegroundColor Green
    Read-Host -Prompt "Stiskněte Enter pro pokračování"
}
# ═══════════════════════════════════════════════════════════════════════════
# MODULE EXPORT
# ═══════════════════════════════════════════════════════════════════════════
function Invoke-ModuleEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $ModuleContext
    )
    if ($null -eq $ModuleContext) {
        throw [System.ArgumentNullException]::new('ModuleContext')
    }
    Show-RevertMenu
}
Export-ModuleMember -Function @(
    'Show-RevertMenu',
    'Invoke-RevertToDefaults',
    'Invoke-ModuleEntry'
)