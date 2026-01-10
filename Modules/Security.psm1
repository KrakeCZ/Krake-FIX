# ═══════════════════════════════════════════════════════════════════════════
# Module: Security.psm1 - Security Hazard Tweaks (RISKY!)
# ═══════════════════════════════════════════════════════════════════════════
# Project:      KRAKE-FIX v2 Modular
# Version:      2.0.0
# Author:       KRAKE-FIX Team
# Created:      2025-10-29
# Last Updated: 2025-10-29
# ═══════════════════════════════════════════════════════════════════════════
# Description:  Menu pro rizikové bezpečnostní tweaky (Spectre/Meltdown,
#               VBS, HVCI, LSA, TSX, Defender, Windows Update disable)
#               ⚠️  POZOR: Tyto tweaky SNIŽUJÍ BEZPEČNOST systému!
# Category:     Security Hazard / Performance Tweaks
# Dependencies: Core.psm1 (Invoke-RevertToDefaults), Recovery.psm1 (Backup)
# Admin Rights: REQUIRED (Registry HKLM, Services)
# ═══════════════════════════════════════════════════════════════════════════
# ⚠️  SECURITY & COMPLIANCE NOTICE
# ═══════════════════════════════════════════════════════════════════════════
# • ⚠️  WARNING: This module DISABLES security features!
# • Designed for educational, testing, and gaming/performance purposes ONLY
# • Tweaks include: Spectre/Meltdown mitigations OFF, VBS OFF, HVCI OFF,
#   LSA Protection OFF, TSX OFF, Defender OFF, Windows Update OFF
# • Author assumes no liability for misuse outside academic context
# ═══════════════════════════════════════════════════════════════════════════
# ⚠️ Tento modul může měnit systémové nastavení.
# Používej pouze ve studijním / testovacím prostředí.
# Autor neručí za zneužití mimo akademické účely.
# ===========================================================
#Requires -Version 5.1
#Requires -RunAsAdministrator
using namespace System.Management.Automation
# ───────────────────────────────────────────────────────────────────────────
# MODULE INITIALIZATION
# ───────────────────────────────────────────────────────────────────────────
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Module-level variables (private)
$script:ModuleName = 'Security'
$script:ModuleVersion = '2.0.0'
# NOTE: Core.psm1 is loaded by Main.ps1 before this module
# No need to manually import it here (would cause duplicate import issues)
# ═══════════════════════════════════════════════════════════════════════════
# PRIVATE HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════
<#
.SYNOPSIS
    Apply or revert security tweaks by category.
.DESCRIPTION
    Comprehensive security tweaks implementation for KRAKE-FIX v2.
    Supports 10+ categories including bcdedit operations.
.PARAMETER Category
    Tweak category (MitigationsCPU, VBS, Integrity, LSA, TSX, etc.)
.PARAMETER Apply
    If specified, applies tweaks. If omitted, reverts to defaults.
.NOTES
    Based on KRAKE-FIX-v1.ps1 Invoke-RevertToDefaults (lines 12971-13584)
    Uses Invoke-WithPrivilege from Core.psm1 for SYSTEM operations
#>
# ═══════════════════════════════════════════════════════════════════════════
# MODULE DEPENDENCIES
# ═══════════════════════════════════════════════════════════════════════════
# Use Core module functions (Write-CoreLog, Invoke-AsSystem, etc.)
# Loaded by Main.ps1 - only import if running standalone
if (-not (Get-Command Write-CoreLog -ErrorAction SilentlyContinue)) {
    $ModulePath = Split-Path -Parent $PSScriptRoot
    $CoreModule = Join-Path $ModulePath "Modules\Core.psm1"
    if (Test-Path $CoreModule) {
        Import-Module $CoreModule -Force -ErrorAction Stop
    }
    else {
        Write-Warning "Core.psm1 not found - some functionality unavailable"
    }
}
# ═══════════════════════════════════════════════════════════════════════════
# INVOKE-REVERTTODEFAULTS - V1 FUNKČNÍ IMPLEMENTACE
# ═══════════════════════════════════════════════════════════════════════════
<#
.SYNOPSIS
    Aplikuje nebo obnovuje bezpečnostní tweaky (V1 FUNKČNÍ VERZE)
.DESCRIPTION
    Přesná 1:1 kopie Invoke-RevertToDefaults z KRAKE-FIX-v1.ps1 (řádky 12971-13584)
    Používá Invoke-AsSystem z Core.psm1 pro SYSTEM operace
.PARAMETER Category
    Kategorie tweaku (MitigationsCPU, VBS, Integrity, LSA, TSX, etc.)
.PARAMETER Apply
    Pokud je zadán, aplikuje tweaky. Pokud není, obnovuje výchozí hodnoty.
.NOTES
#>
function Invoke-RevertToDefaults {
    param(
        [string]$Category,
        [switch]$Apply
    )
    if (!$Apply) {
        if ($Category -notin @('Win32Prio', 'HIDLatency', 'NvidiaGPU', 'IntelGPU')) {
            if ((Read-Host -Prompt "Opravdu chcete obnovit kategorii '$Category'? (Ano/Ne)") -notmatch '^a') { Write-Host "Operace zrušena."; return }
        }
    }
    $action = if ($Apply) { "Aplikuji" } else { "Obnovuji" }
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
        } -ArgumentList $regPath, $Apply
    }
    # ROZDĚLENO: WinUpdate na dvě samostatné kategorie (obě starší metody)
    # Kategorie pro SLUŽBY (blokace Win Update služeb)
    if ($Category -in @('WinUpdateServices', 'All')) {
        Write-Host "  -> $action Windows Update služby (blokace služeb)..." -ForegroundColor Gray
        # POZNÁMKA: Pro služby používá hlavní menu dedikované funkce Invoke-WPFUpdatesdisable/default
        # Tato sekce je pro kompatibilitu s 'All' restore
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
    # Kategorie pro OVLADAČE přes Windows Update (blokace ovladačů přes registry)
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
    if ($Category -in @('VBS', 'All')) {
        Write-Host "  -> $action VBS & Hyper-V..." -ForegroundColor Cyan
        # Registry operace MUSÍ běžet jako SYSTEM (HKLM:\SYSTEM\CurrentControlSet\)
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
        } -ArgumentList $Apply
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
    if ($Category -in @('Integrity', 'All')) {
        Write-Host "  -> $action Integrita Jádra (HVCI)..." -ForegroundColor Cyan
        if ($Apply) {
            # Kontrola SecureBoot před aplikací
            try {
                $secureBoot = Confirm-SecureBootUEFI
                if ($secureBoot) {
                    Write-Host ""
                    Write-Warning "=========================================="
                    Write-Warning "  SECURE BOOT JE ZAPNUTÝ!"
                    Write-Warning "=========================================="
                    Write-Host "Pro úspěšné vypnutí Memory Integrity (HVCI) je nutné:" -ForegroundColor Yellow
                    Write-Host "1. Vypnout Secure Boot v BIOS/UEFI" -ForegroundColor Yellow
                    Write-Host "2. Restartovat počítač" -ForegroundColor Yellow
                    Write-Host "3. Znovu spustit tento skript" -ForegroundColor Yellow
                    Write-Host ""
                }
            }
            catch {
                Write-Host "  -> Nelze zjistit stav Secure Boot (pravděpodobně ne-UEFI systém)" -ForegroundColor Gray
            }
            # Kontrola současného stavu bcdedit PŘED aplikací
            Write-Host "  -> Kontroluji současný stav bcdedit..." -ForegroundColor Yellow
            try {
                $bcdOutput = bcdedit.exe /enum "{current}" | Out-String
                if ($bcdOutput -match "nointegritychecks\s+Yes") {
                    Write-Host "  -> bcdedit: nointegritychecks je již ZAPNUTÝ (integrity checks vypnuty)" -ForegroundColor Green
                }
                else {
                    Write-Host "  -> bcdedit: nointegritychecks je VYPNUTÝ (integrity checks aktivní)" -ForegroundColor Cyan
                }
            }
            catch {
                Write-Warning "  -> Nepodařilo se načíst stav bcdedit"
            }
            # Aplikace
            Write-Host "  -> Aplikuji vypnutí Memory Integrity (HVCI)..." -ForegroundColor Cyan
            # Registry operace MUSÍ běžet jako SYSTEM (HKLM:\SYSTEM\CurrentControlSet\)
            Invoke-AsSystem -ScriptBlock {
                Write-Host "  -> [SYSTEM] Nastavuji HVCI registry..." -ForegroundColor Gray
                if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
                    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 0 -Type DWord -Force -EA 0
                Write-Host "  -> [SYSTEM] Registry HVCI Enabled = 0" -ForegroundColor Green
            }
            # bcdedit může běžet jako Admin
            try {
                bcdedit.exe /set nointegritychecks on | Out-Null
                Write-Host "  -> bcdedit příkaz proveden: /set nointegritychecks on" -ForegroundColor Green
            }
            catch {
                Write-Warning "  -> bcdedit příkaz selhal: $($_.Exception.Message)"
            }
            # Kontrola stavu PO aplikaci
            Write-Host "  -> Kontroluji stav bcdedit PO aplikaci..." -ForegroundColor Yellow
            Start-Sleep -Milliseconds 500
            try {
                $bcdOutputAfter = bcdedit.exe /enum "{current}" | Out-String
                if ($bcdOutputAfter -match "nointegritychecks\s+Yes") {
                    Write-Host "  -> ✅ bcdedit: nointegritychecks úspěšně ZAPNUT" -ForegroundColor Green
                    Write-Host "  -> ✅ Memory Integrity (HVCI) bude vypnutý po restartu" -ForegroundColor Green
                }
                else {
                    Write-Warning "  -> ⚠️ bcdedit: nointegritychecks nebyl aplikován!"
                    Write-Warning "  -> Možná příčina: Secure Boot je aktivní"
                }
            }
            catch {
                Write-Warning "  -> Nepodařilo se ověřit stav bcdedit po aplikaci"
            }
        }
        else {
            # Restore (obnova)
            Write-Host "  -> Obnovuji Memory Integrity (HVCI)..." -ForegroundColor Cyan
            # Kontrola Secure Boot před obnovením (informativní)
            try {
                $secureBoot = Confirm-SecureBootUEFI
                if (-not $secureBoot) {
                    Write-Host ""
                    Write-Host "  -> INFO: Secure Boot je VYPNUTÝ" -ForegroundColor Yellow
                    Write-Host "  -> Pro úplné obnovení HVCI doporučujeme zapnout Secure Boot v BIOS/UEFI" -ForegroundColor Yellow
                    Write-Host ""
                }
            }
            catch {
                Write-Host "  -> Nelze zjistit stav Secure Boot (pravděpodobně ne-UEFI systém)" -ForegroundColor Gray
            }
            # Kontrola současného stavu bcdedit PŘED obnovením
            Write-Host "  -> Kontroluji současný stav bcdedit..." -ForegroundColor Yellow
            try {
                $bcdOutput = bcdedit.exe /enum "{current}" | Out-String
                if ($bcdOutput -match "nointegritychecks\s+Yes") {
                    Write-Host "  -> bcdedit: nointegritychecks je ZAPNUTÝ (integrity checks vypnuty)" -ForegroundColor Cyan
                }
                else {
                    Write-Host "  -> bcdedit: nointegritychecks je již VYPNUTÝ (integrity checks aktivní)" -ForegroundColor Green
                }
            }
            catch {
                Write-Warning "  -> Nepodařilo se načíst stav bcdedit"
            }
            # Aplikace obnovy
            Write-Host "  -> Obnovuji Memory Integrity (HVCI)..." -ForegroundColor Cyan
            # Registry operace MUSÍ běžet jako SYSTEM
            Invoke-AsSystem -ScriptBlock {
                Write-Host "  -> [SYSTEM] Obnovuji HVCI registry..." -ForegroundColor Gray
                if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
                    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 1 -Type DWord -Force -EA 0
                Write-Host "  -> [SYSTEM] Registry HVCI Enabled = 1" -ForegroundColor Green
            }
            # bcdedit může běžet jako Admin
            try { 
                bcdedit.exe /deletevalue nointegritychecks | Out-Null
                Write-Host "  -> bcdedit příkaz proveden: /deletevalue nointegritychecks" -ForegroundColor Green
            }
            catch {
                Write-Host "  -> bcdedit: nointegritychecks již neexistuje nebo bylo odstraněno" -ForegroundColor Gray
            }
            # Kontrola stavu PO obnovení
            Write-Host "  -> Kontroluji stav bcdedit PO obnovení..." -ForegroundColor Yellow
            Start-Sleep -Milliseconds 500
            try {
                $bcdOutputAfter = bcdedit.exe /enum "{current}" | Out-String
                if ($bcdOutputAfter -notmatch "nointegritychecks\s+Yes") {
                    Write-Host "  -> ✅ bcdedit: nointegritychecks úspěšně ODSTRANĚN" -ForegroundColor Green
                    Write-Host "  -> ✅ Memory Integrity (HVCI) bude zapnutý po restartu" -ForegroundColor Green
                }
                else {
                    Write-Warning "  -> ⚠️ bcdedit: nointegritychecks stále existuje!"
                    Write-Warning "  -> Možná příčina: Secure Boot je vypnutý nebo systémové omezení"
                }
            }
            catch {
                Write-Warning "  -> Nepodařilo se ověřit stav bcdedit po obnovení"
            }
        }
    }
    if ($Category -in @('LSA', 'All')) {
        Write-Host "  -> $action LSA Ochrana..." -ForegroundColor Cyan
        # Registry operace MUSÍ běžet jako SYSTEM (HKLM:\SYSTEM\CurrentControlSet\)
        Invoke-AsSystem -ScriptBlock {
            param($IsApply)
            if ($IsApply) {
                Write-Host "  -> [SYSTEM] Vypínám LSA ochranu..." -ForegroundColor Gray
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 0 -Type DWord -Force -EA 0
                Write-Host "  -> [SYSTEM] LSA ochrana vypnuta (LsaCfgFlags=0)" -ForegroundColor Green
            }
            else {
                Write-Host "  -> [SYSTEM] Obnovuji LSA ochranu..." -ForegroundColor Gray
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1 -Type DWord -Force -EA 0
                Write-Host "  -> [SYSTEM] LSA ochrana obnovena (LsaCfgFlags=1)" -ForegroundColor Green
            }
        } -ArgumentList $Apply
    }
    if ($Category -in @('TSX', 'All')) {
        Write-Host "  -> $action TSX Instrukce..." -ForegroundColor Cyan
        # Registry operace MUSÍ běžet jako SYSTEM (HKLM:\SYSTEM\CurrentControlSet\)
        Invoke-AsSystem -ScriptBlock {
            param($IsApply)
            $tsxPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
            if ($IsApply) {
                Write-Host "  -> [SYSTEM] Vypínám Intel TSX..." -ForegroundColor Gray
                if (-not (Test-Path $tsxPath)) {
                    New-Item -Path $tsxPath -Force | Out-Null
                }
                Set-ItemProperty -Path $tsxPath -Name "DisableTsx" -Value 1 -Type DWord -Force -EA 0
                Write-Host "  -> [SYSTEM] TSX vypnuto (DisableTsx=1)" -ForegroundColor Green
            }
            else {
                Write-Host "  -> [SYSTEM] Obnovuji Intel TSX..." -ForegroundColor Gray
                Remove-ItemProperty -Path $tsxPath -Name "DisableTsx" -Force -EA 0
                Write-Host "  -> [SYSTEM] TSX obnoveno" -ForegroundColor Green
            }
        } -ArgumentList $Apply
    }
    if ($Category -in @('Defender', 'DefenderRT', 'All')) {
        Write-Host "  -> $action MS Defender (Real-time ochrana)..." -ForegroundColor Cyan
        if ($Apply) {
            if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null }
            if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Force | Out-Null }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force -EA 0
        }
        else {
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" -Name "DisableRealtimeMonitoring" -Force -EA 0
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableRealtimeMonitoring" -Force -EA 0
        }
    }
    if ($Category -in @('DefenderBlock', 'All')) {
        Write-Host "  -> $action MS Defender (BLOKACE - Registry + Služby)..." -ForegroundColor Cyan
        if ($Apply) {
            if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null }
            if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Force | Out-Null }
            if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) { New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 1 -Type DWord -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBlockAtFirstSeen" -Value 1 -Type DWord -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Value 1 -Type DWord -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisablePrivacyMode" -Value 1 -Type DWord -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Value 0 -Type DWord -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Value 0 -Type DWord -Force -EA 0
            # Zakázat VŠECHNY Defender služby
            Invoke-AsSystem -ScriptBlock {
                $defenderServices = @("WinDefend", "SecurityHealthService", "WdNisSvc", "Sense", "wscsvc")
                foreach ($svc in $defenderServices) {
                    if (Get-Service $svc -EA 0) { 
                        Write-Host "  -> [SYSTEM] Zakazuji službu: $svc" -ForegroundColor Yellow
                        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name Start -Value 4 -Force -EA 0
                        Stop-Service $svc -Force -EA 0 
                    }
                }
            }
        }
        else {
            Write-Host "  -> Obnovuji Defender registry..." -ForegroundColor Yellow
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Force -EA 0
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Force -EA 0
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableBlockAtFirstSeen" -Force -EA 0
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableIOAVProtection" -Force -EA 0
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisablePrivacyMode" -Force -EA 0
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -Name "DisableRealtimeMonitoring" -Force -EA 0
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Force -EA 0
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Force -EA 0
            Write-Host "  -> Obnovuji Defender služby..." -ForegroundColor Yellow
            Invoke-AsSystem -ScriptBlock {
                $defenderServices = @("WinDefend", "SecurityHealthService", "WdNisSvc", "Sense", "wscsvc")
                foreach ($svcName in $defenderServices) {
                    if (Get-Service $svcName -EA 0) {
                        # Výchozí hodnoty pro Defender služby
                        $startType = switch ($svcName) {
                            "WinDefend" { 2 }           # Automatic
                            "SecurityHealthService" { 3 } # Manual
                            "WdNisSvc" { 3 }            # Manual
                            "Sense" { 3 }               # Manual
                            "wscsvc" { 2 }              # Automatic
                            default { 3 }
                        }
                        Write-Host "  -> [SYSTEM] Obnovuji $svcName na výchozí StartType=$startType" -ForegroundColor Cyan
                        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -Name Start -Value $startType -Force -EA 0
                        # Pokusit se spustit automatické služby
                        if ($startType -eq 2) {
                            Start-Service $svcName -EA 0
                        }
                    }
                }
            }
            Write-Host "  -> Defender služby obnoveny!" -ForegroundColor Green
            Write-Host "  -> DŮLEŽITÉ: Pro úplné obnovení Defenderu je nutný RESTART PC!" -ForegroundColor Yellow
        }
    }
    if ($Category -in @('GamingPerf', 'All')) {
        Write-Host "  -> $action Gaming Performance Tweaks..." -ForegroundColor Cyan
        if ($Apply) {
            # SOFTWARE registry cesty - Admin OK
            Write-Host "  -> Aplikuji multimedia tweaky..." -ForegroundColor Gray
            if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Force | Out-Null }
            if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games")) { New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Force | Out-Null }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 0 -Type DWord -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 0xffffffff -Type DWord -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NoLazyMode" -Value 1 -Type DWord -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "AlwaysOn" -Value 1 -Type DWord -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Affinity" -Value 0x00000000 -Type DWord -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Background Only" -Value "False" -Type String -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Clock Rate" -Value 0x00002710 -Type DWord -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Value 0x00000008 -Type DWord -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Value 0x00000006 -Type DWord -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Value "High" -Type String -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Value "High" -Type String -Force -EA 0
            # SYSTEM registry cesty + služby MUSÍ jako SYSTEM
            Invoke-AsSystem -ScriptBlock {
                Write-Host "  -> [SYSTEM] Aplikuji gaming tweaky (Memory Management)..." -ForegroundColor Gray
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "IoPageLockLimit" -Value 0x30000000 -Type DWord -Force -EA 0
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 1 -Type DWord -Force -EA 0
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Value "150" -Type String -Force -EA 0
                Write-Host "  -> [SYSTEM] Zakazuji SysMain a WSearch..." -ForegroundColor Gray
                if (Get-Service "SysMain" -EA 0) { Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain" -Name Start -Value 4 -Force; Stop-Service "SysMain" -Force -EA 0 }
                if (Get-Service "WSearch" -EA 0) { Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -Name Start -Value 4 -Force; Stop-Service "WSearch" -Force -EA 0 }
                Write-Host "  -> [SYSTEM] Gaming tweaky aplikovány" -ForegroundColor Green
            }
        }
        else {
            # Restore - SOFTWARE registry cesty jako Admin
            Write-Host "  -> Obnovuji multimedia tweaky..." -ForegroundColor Gray
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 20 -Type DWord -Force -EA 0
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 10 -Type DWord -Force -EA 0
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NoLazyMode" -Force -EA 0
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "AlwaysOn" -Force -EA 0
            # Restore - SYSTEM registry cesty + služby jako SYSTEM
            Invoke-AsSystem -ScriptBlock {
                Write-Host "  -> [SYSTEM] Obnovuji gaming tweaky (Memory Management)..." -ForegroundColor Gray
                Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "IoPageLockLimit" -Force -EA 0
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "DisablePagingExecutive" -Value 0 -Type DWord -Force -EA 0
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Value "2000" -Type String -Force -EA 0
                Write-Host "  -> [SYSTEM] Obnovuji SysMain a WSearch..." -ForegroundColor Gray
                if (Get-Service "SysMain" -EA 0) { Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SysMain" -Name Start -Value 2 -Force; Start-Service "SysMain" -EA 0 }
                if (Get-Service "WSearch" -EA 0) { Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WSearch" -Name Start -Value 2 -Force; Start-Service "WSearch" -EA 0 }
                Write-Host "  -> [SYSTEM] Gaming tweaky obnoveny" -ForegroundColor Green
            }
        }
    }
    if ($Category -in @('TelemetryServices', 'All')) {
        Write-Host "  -> $action Telemetrické služby..." -ForegroundColor Cyan
        if ($Apply) {
            Invoke-AsSystem -ScriptBlock {
                $services = @("DiagTrack", "diagsvc", "diagnosticshub.standardcollector.service", "dmwappushservice", "lfsvc", "MapsBroker", "NaturalAuthentication", "TroubleshootingSvc", "tzautoupdate", "WdiServiceHost", "WdiSystemHost", "wisvc")
                foreach ($s in $services) { 
                    if (Get-Service $s -EA 0) { 
                        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$s" -Name Start -Value 4 -Force -EA 0
                        Stop-Service $s -Force -EA 0 
                    } 
                }
            }
        }
        else {
            Invoke-AsSystem -ScriptBlock {
                if (Get-Service "DiagTrack" -EA 0) { Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack" -Name Start -Value 2 -Force; Start-Service "DiagTrack" -EA 0 }
                if (Get-Service "diagsvc" -EA 0) { Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\diagsvc" -Name Start -Value 3 -Force }
                if (Get-Service "dmwappushservice" -EA 0) { Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name Start -Value 3 -Force }
            }
        }
    }
    if ($Category -in @('FullAdmin', 'All')) {
        Write-Host "  -> $action 'Full Admin Control' Menu..." -ForegroundColor Cyan
        if ($Apply) {
            $regContent = @'
Windows Registry Editor Version 5.00
[HKEY_CLASSES_ROOT\*\shell\runas]
@="Full Admin Control"
"NoWorkingDirectory"=""
[HKEY_CLASSES_ROOT\*\shell\runas\command]
@="cmd.exe /c takeown /f \"%1\" && icacls \"%1\" /grant administrators:F"
[HKEY_CLASSES_ROOT\Directory\shell\runas]
@="Full Admin Control"
"NoWorkingDirectory"=""
[HKEY_CLASSES_ROOT\Directory\shell\runas\command]
@="cmd.exe /c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant administrators:F /t"
'@
            $tmp = Join-Path $env:TEMP "tmp.reg"; $regContent | Set-Content -Path $tmp -Encoding Unicode; Start-Process reg -Arg "import `"$tmp`"" -Wait -WindowStyle Hidden; Remove-Item $tmp -Force
        }
        else {
            Invoke-AsSystem -ScriptBlock {
                Remove-Item -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas' -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas' -Recurse -Force -ErrorAction SilentlyContinue
            }
            Write-Host "  -> Vynucuji obnovení Průzkumníka Windows (může probliknout obrazovka)..." -ForegroundColor Cyan
            try { Stop-Process -Name explorer -Force -ErrorAction Stop } catch {}
            Start-Sleep -Seconds 1
            Start-Process explorer
        }
    }
    if ($Category -in @('OtherServices', 'All')) {
        Write-Host "  -> $action Doplňkové bezpečnostní služby..." -ForegroundColor Cyan
        if ($Apply) {
            Invoke-AsSystem -ScriptBlock {
                $services = @("VSS", "SecurityHealthService", "wscsvc", "BDESVC", "AppIDSvc", "EFS", "fhsvc", "RemoteRegistry", "Eaphost", "PolicyAgent")
                foreach ($s in $services) { if (Get-Service $s -EA 0) { Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$s" -Name Start -Value 4 -Force; Stop-Service $s -Force -EA 0 } }
            }
        }
        else {
            Invoke-AsSystem -ScriptBlock {
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\VSS" -Name Start -Value 3 -Force
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityHealthService" -Name Start -Value 2 -Force; Start-Service "SecurityHealthService" -EA 0
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\wscsvc" -Name Start -Value 2 -Force; Start-Service "wscsvc" -EA 0
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\BDESVC" -Name Start -Value 3 -Force
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc" -Name Start -Value 3 -Force
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\EFS" -Name Start -Value 3 -Force
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\fhsvc" -Name Start -Value 3 -Force
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry" -Name Start -Value 4 -Force
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Eaphost" -Name Start -Value 3 -Force
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\PolicyAgent" -Name Start -Value 2 -Force
            }
        }
    }
    if ($Category -in @('Win32Prio', 'All')) {
        Write-Host "  -> $action Win32PrioritySeparation na výchozí hodnotu..." -ForegroundColor Cyan
        # Registry operace MUSÍ běžet jako SYSTEM (HKLM:\SYSTEM\CurrentControlSet\)
        Invoke-AsSystem -ScriptBlock {
            Write-Host "  -> [SYSTEM] Nastavuji Win32PrioritySeparation=2..." -ForegroundColor Gray
            if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl")) {
                New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 2 -Type DWord -Force
            Write-Host "  -> [SYSTEM] Win32PrioritySeparation=2 (výchozí hodnota)" -ForegroundColor Green
        }
    }
    if ($Category -in @('HIDLatency', 'All')) {
        Write-Host "  -> $action Latence Vstupu na výchozí hodnoty..." -ForegroundColor Cyan
        # Registry operace MUSÍ běžet jako SYSTEM (HKLM:\SYSTEM\CurrentControlSet\Services\)
        Invoke-AsSystem -ScriptBlock {
            Write-Host "  -> [SYSTEM] Obnovuji HID latence..." -ForegroundColor Gray
            if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters")) {
                New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Force | Out-Null
            }
            if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters")) {
                New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Force | Out-Null
            }
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters" -Name "KeyboardDataQueueSize" -Value 100 -Type DWord -Force
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters" -Name "MouseDataQueueSize" -Value 100 -Type DWord -Force
            Write-Host "  -> [SYSTEM] HID latence obnoveny (100/100)" -ForegroundColor Green
        }
    }
    if ($Category -in @('NvidiaGPU')) {
        Write-Host "  -> $action NVIDIA GPU Tweaks..." -ForegroundColor Cyan
        if (!$Apply) {
            Write-Host "  -> NVIDIA GPU Tweaks (restore není implementováno v V1 verzi)" -ForegroundColor Yellow
        }
    }
    if ($Category -in @('IntelGPU')) {
        Write-Host "  -> $action Intel iGPU Tweaks..." -ForegroundColor Cyan
        if (!$Apply) {
            Write-Host "  -> Intel iGPU Tweaks (restore není implementováno v V1 verzi)" -ForegroundColor Yellow
        }
    }
    if (!$Apply) { Write-Host "=================================================="; Write-Host "OBNOVA DOKONČENA. Některé změny vyžadují restart PC." -ForegroundColor Green }
}
# ═══════════════════════════════════════════════════════════════════════════
# INVOKE-SECURITYTWEAKS - STARÁ NEFUNKČNÍ IMPLEMENTACE (DEPRECATED)
# ═══════════════════════════════════════════════════════════════════════════
function Invoke-SecurityTweaks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'MitigationsCPU', 'WinUpdateServices', 'WinUpdateDrivers',
            'VBS', 'Integrity', 'LSA', 'TSX',
            'DefenderRT', 'DefenderBlock', 
            'FullAdmin', 'OtherServices', 'TelemetryServices',
            'TimerResolution', 'All'
        )]
        [string]$Category,
        [switch]$Apply
    )
    $action = if ($Apply) { "Aplikuji" } else { "Obnovuji" }
    # Audit log
    if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
        Write-CoreLog -Message "Security tweaks: $action category $Category" -Level Warning
    }
    # === KATEGORIE 1: CPU MITIGATIONS (Spectre/Meltdown) ===
    if ($Category -in @('MitigationsCPU', 'All')) {
        Write-Host "  -> $action Mitigace CPU..." -ForegroundColor Cyan
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        # Registry operace vyžadují SYSTEM
        $result = Invoke-WithPrivilege -ScriptBlock {
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
        } -ArgumentList @($regPath, $Apply) -RequiredPrivilege 'System'
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "CPU Mitigations: $action completed (Success: $($result.Success))" -Level Info
        }
    }
    # === KATEGORIE 2: WINDOWS UPDATE SERVICES ===
    if ($Category -in @('WinUpdateServices', 'All')) {
        Write-Host "  -> $action Windows Update služby..." -ForegroundColor Gray
        $result = Invoke-WithPrivilege -ScriptBlock {
            param($IsApply)
            $services = @("wuauserv", "BITS", "UsoSvc", "WaaSMedicSvc", "DoSvc")
            if ($IsApply) {
                foreach ($s in $services) { 
                    if (Get-Service $s -ErrorAction SilentlyContinue) { 
                        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$s" -Name Start -Value 4 -Force 
                        Stop-Service $s -Force -ErrorAction SilentlyContinue
                        Write-Host "  -> [SYSTEM] Služba $s zakázána" -ForegroundColor Gray
                    }
                }
            }
            else {
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv" -Name Start -Value 2 -Force; Start-Service "wuauserv" -ErrorAction SilentlyContinue
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\BITS" -Name Start -Value 2 -Force; Start-Service "BITS" -ErrorAction SilentlyContinue
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\UsoSvc" -Name Start -Value 2 -Force; Start-Service "UsoSvc" -ErrorAction SilentlyContinue
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" -Name Start -Value 3 -Force
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DoSvc" -Name Start -Value 2 -Force; Start-Service "DoSvc" -ErrorAction SilentlyContinue
                Write-Host "  -> [SYSTEM] Windows Update služby obnoveny" -ForegroundColor Gray
            }
        } -ArgumentList @($Apply) -RequiredPrivilege 'System'
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "Windows Update Services: $action completed" -Level Info
        }
    }
    # === KATEGORIE 3: WINDOWS UPDATE DRIVERS (Registry) ===
    if ($Category -in @('WinUpdateDrivers', 'All')) {
        Write-Host "  -> $action Windows Update ovladače (registry)..." -ForegroundColor Gray
        if ($Apply) {
            if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) { 
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null 
            }
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
        }
        else {
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Force -ErrorAction SilentlyContinue
        }
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "Windows Update Drivers: $action completed" -Level Info
        }
    }
    # === KATEGORIE 4: VBS (Virtualization-Based Security) + bcdedit ===
    if ($Category -in @('VBS', 'All')) {
        Write-Host "  -> $action VBS & Hyper-V..." -ForegroundColor Cyan
        # Registry operace vyžadují SYSTEM
        $result = Invoke-WithPrivilege -ScriptBlock {
            param($IsApply)
            if ($IsApply) {
                Write-Host "  -> [SYSTEM] Vypínám VBS..." -ForegroundColor Gray
                if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard")) {
                    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                Write-Host "  -> [SYSTEM] VBS vypnuto (registry)" -ForegroundColor Green
            }
            else {
                Write-Host "  -> [SYSTEM] Obnovuji VBS..." -ForegroundColor Gray
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                Write-Host "  -> [SYSTEM] VBS obnoveno (registry)" -ForegroundColor Green
            }
        } -ArgumentList @($Apply) -RequiredPrivilege 'System'
        # bcdedit může běžet jako Admin
        if ($Apply) {
            bcdedit.exe /set hypervisorlaunchtype off | Out-Null
            Write-Host "  -> bcdedit: hypervisor launch vypnut" -ForegroundColor Green
        }
        else {
            bcdedit.exe /set hypervisorlaunchtype auto | Out-Null
            try { bcdedit.exe /deletevalue vm | Out-Null } catch {}
            Write-Host "  -> bcdedit: hypervisor launch obnoven" -ForegroundColor Green
        }
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "VBS: $action completed (bcdedit + registry)" -Level Info
        }
    }
    # === KATEGORIE 5: INTEGRITY (HVCI - Memory Integrity) + bcdedit + Secure Boot ===
    if ($Category -in @('Integrity', 'All')) {
        Write-Host "  -> $action Integrita Jádra (HVCI)..." -ForegroundColor Cyan
        if ($Apply) {
            # Kontrola SecureBoot
            try {
                $secureBoot = Confirm-SecureBootUEFI
                if ($secureBoot) {
                    Write-Host ""
                    Write-Warning "=========================================="
                    Write-Warning "  SECURE BOOT JE ZAPNUTÝ!"
                    Write-Warning "=========================================="
                    Write-Host "Pro úspěšné vypnutí Memory Integrity (HVCI) je nutné:" -ForegroundColor Yellow
                    Write-Host "1. Vypnout Secure Boot v BIOS/UEFI" -ForegroundColor Yellow
                    Write-Host "2. Restartovat počítač" -ForegroundColor Yellow
                    Write-Host "3. Znovu spustit tento skript" -ForegroundColor Yellow
                    Write-Host ""
                }
            }
            catch {
                Write-Host "  -> Nelze zjistit stav Secure Boot (pravděpodobně ne-UEFI systém)" -ForegroundColor Gray
            }
            # Kontrola bcdedit PŘED
            Write-Host "  -> Kontroluji současný stav bcdedit..." -ForegroundColor Yellow
            try {
                $bcdOutput = bcdedit.exe /enum "{current}" | Out-String
                if ($bcdOutput -match "nointegritychecks\s+Yes") {
                    Write-Host "  -> bcdedit: nointegritychecks je již ZAPNUTÝ" -ForegroundColor Green
                }
                else {
                    Write-Host "  -> bcdedit: nointegritychecks je VYPNUTÝ" -ForegroundColor Cyan
                }
            }
            catch {
                Write-Warning "  -> Nepodařilo se načíst stav bcdedit"
            }
            # Registry (SYSTEM)
            $result = Invoke-WithPrivilege -ScriptBlock {
                Write-Host "  -> [SYSTEM] Nastavuji HVCI registry..." -ForegroundColor Gray
                if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
                    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                Write-Host "  -> [SYSTEM] Registry HVCI Enabled = 0" -ForegroundColor Green
            } -RequiredPrivilege 'System'
            # bcdedit (Admin)
            try {
                bcdedit.exe /set nointegritychecks on | Out-Null
                Write-Host "  -> bcdedit příkaz proveden: /set nointegritychecks on" -ForegroundColor Green
            }
            catch {
                Write-Warning "  -> bcdedit příkaz selhal: $($_.Exception.Message)"
            }
            # Kontrola PO
            Write-Host "  -> Kontroluji stav bcdedit PO aplikaci..." -ForegroundColor Yellow
            Start-Sleep -Milliseconds 500
            try {
                $bcdOutputAfter = bcdedit.exe /enum "{current}" | Out-String
                if ($bcdOutputAfter -match "nointegritychecks\s+Yes") {
                    Write-Host "  -> ✅ bcdedit: nointegritychecks úspěšně ZAPNUT" -ForegroundColor Green
                    Write-Host "  -> ✅ Memory Integrity (HVCI) bude vypnutý po restartu" -ForegroundColor Green
                }
                else {
                    Write-Warning "  -> ⚠️  bcdedit: nointegritychecks nebyl aplikován!"
                    Write-Warning "  -> Možná příčina: Secure Boot je aktivní"
                }
            }
            catch {
                Write-Warning "  -> Nepodařilo se ověřit stav bcdedit po aplikaci"
            }
        }
        else {
            # Restore
            Write-Host "  -> Obnovuji Memory Integrity (HVCI)..." -ForegroundColor Cyan
            # Registry (SYSTEM)
            $result = Invoke-WithPrivilege -ScriptBlock {
                Write-Host "  -> [SYSTEM] Obnovuji HVCI registry..." -ForegroundColor Gray
                if (-not (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
                    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                Write-Host "  -> [SYSTEM] Registry HVCI Enabled = 1" -ForegroundColor Green
            } -RequiredPrivilege 'System'
            # bcdedit (Admin)
            try { 
                bcdedit.exe /deletevalue nointegritychecks | Out-Null
                Write-Host "  -> bcdedit příkaz proveden: /deletevalue nointegritychecks" -ForegroundColor Green
            }
            catch {
                Write-Host "  -> bcdedit: nointegritychecks již neexistuje" -ForegroundColor Gray
            }
            # Kontrola PO
            Write-Host "  -> Kontroluji stav bcdedit PO obnovení..." -ForegroundColor Yellow
            Start-Sleep -Milliseconds 500
            try {
                $bcdOutputAfter = bcdedit.exe /enum "{current}" | Out-String
                if ($bcdOutputAfter -notmatch "nointegritychecks\s+Yes") {
                    Write-Host "  -> ✅ bcdedit: nointegritychecks úspěšně ODSTRANĚN" -ForegroundColor Green
                    Write-Host "  -> ✅ Memory Integrity (HVCI) bude zapnutý po restartu" -ForegroundColor Green
                }
                else {
                    Write-Warning "  -> ⚠️  bcdedit: nointegritychecks stále existuje!"
                }
            }
            catch {
                Write-Warning "  -> Nepodařilo se ověřit stav bcdedit"
            }
        }
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "Integrity (HVCI): $action completed (bcdedit + registry + Secure Boot check)" -Level Info
        }
    }
    # === KATEGORIE 6: LSA PROTECTION ===
    if ($Category -in @('LSA', 'All')) {
        Write-Host "  -> $action LSA Ochrana..." -ForegroundColor Cyan
        $result = Invoke-WithPrivilege -ScriptBlock {
            param($IsApply)
            if ($IsApply) {
                Write-Host "  -> [SYSTEM] Vypínám LSA ochranu..." -ForegroundColor Gray
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                Write-Host "  -> [SYSTEM] LSA ochrana vypnuta (LsaCfgFlags=0)" -ForegroundColor Green
            }
            else {
                Write-Host "  -> [SYSTEM] Obnovuji LSA ochranu..." -ForegroundColor Gray
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                Write-Host "  -> [SYSTEM] LSA ochrana obnovena (LsaCfgFlags=1)" -ForegroundColor Green
            }
        } -ArgumentList @($Apply) -RequiredPrivilege 'System'
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "LSA Protection: $action completed" -Level Info
        }
    }
    # === KATEGORIE 7: TSX (Intel TSX Instructions) ===
    if ($Category -in @('TSX', 'All')) {
        Write-Host "  -> $action TSX Instrukce..." -ForegroundColor Cyan
        $result = Invoke-WithPrivilege -ScriptBlock {
            param($IsApply)
            $tsxPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
            if ($IsApply) {
                Write-Host "  -> [SYSTEM] Vypínám Intel TSX..." -ForegroundColor Gray
                if (-not (Test-Path $tsxPath)) {
                    New-Item -Path $tsxPath -Force | Out-Null
                }
                Set-ItemProperty -Path $tsxPath -Name "DisableTsx" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                Write-Host "  -> [SYSTEM] TSX vypnuto (DisableTsx=1)" -ForegroundColor Green
            }
            else {
                Write-Host "  -> [SYSTEM] Obnovuji Intel TSX..." -ForegroundColor Gray
                Remove-ItemProperty -Path $tsxPath -Name "DisableTsx" -Force -ErrorAction SilentlyContinue
                Write-Host "  -> [SYSTEM] TSX obnoveno" -ForegroundColor Green
            }
        } -ArgumentList @($Apply) -RequiredPrivilege 'System'
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "TSX: $action completed" -Level Info
        }
    }
    # === KATEGORIE 8: DEFENDER REAL-TIME ===
    if ($Category -in @('DefenderRT', 'All')) {
        Write-Host "  -> $action MS Defender Real-Time..." -ForegroundColor Cyan
        $result = Invoke-WithPrivilege -ScriptBlock {
            param($IsApply)
            if ($IsApply) {
                Write-Host "  -> [SYSTEM] Vypínám Defender Real-Time..." -ForegroundColor Gray
                Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
                Write-Host "  -> [SYSTEM] Defender Real-Time vypnut" -ForegroundColor Green
            }
            else {
                Write-Host "  -> [SYSTEM] Obnovuji Defender Real-Time..." -ForegroundColor Gray
                Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
                Write-Host "  -> [SYSTEM] Defender Real-Time obnoven" -ForegroundColor Green
            }
        } -ArgumentList @($Apply) -RequiredPrivilege 'System'
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "Defender Real-Time: $action completed" -Level Info
        }
    }
    # === KATEGORIE 9: DEFENDER BLOCK (Registry + Services) ===
    if ($Category -in @('DefenderBlock', 'All')) {
        Write-Host "  -> $action MS Defender BLOKACE..." -ForegroundColor Red
        $result = Invoke-WithPrivilege -ScriptBlock {
            param($IsApply)
            if ($IsApply) {
                Write-Host "  -> [SYSTEM] Aplikuji Defender blokaci (registry)..." -ForegroundColor Gray
                if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
                    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                # Služby
                $defServices = @("WinDefend", "SecurityHealthService", "WdNisSvc", "Sense", "wscsvc")
                foreach ($s in $defServices) {
                    if (Get-Service $s -ErrorAction SilentlyContinue) {
                        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$s" -Name Start -Value 4 -Force -ErrorAction SilentlyContinue
                        Stop-Service $s -Force -ErrorAction SilentlyContinue
                        Write-Host "  -> [SYSTEM] Služba $s zakázána" -ForegroundColor Gray
                    }
                }
                Write-Host "  -> [SYSTEM] Defender BLOKACE aplikována" -ForegroundColor Green
            }
            else {
                Write-Host "  -> [SYSTEM] Obnovuji Defender..." -ForegroundColor Gray
                Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Force -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiVirus" -Force -ErrorAction SilentlyContinue
                # Služby
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" -Name Start -Value 2 -Force -ErrorAction SilentlyContinue
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityHealthService" -Name Start -Value 3 -Force -ErrorAction SilentlyContinue
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" -Name Start -Value 3 -Force -ErrorAction SilentlyContinue
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" -Name Start -Value 3 -Force -ErrorAction SilentlyContinue
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\wscsvc" -Name Start -Value 2 -Force -ErrorAction SilentlyContinue
                Start-Service "WinDefend" -ErrorAction SilentlyContinue
                Start-Service "wscsvc" -ErrorAction SilentlyContinue
                Write-Host "  -> [SYSTEM] Defender obnoven" -ForegroundColor Green
            }
        } -ArgumentList @($Apply) -RequiredPrivilege 'System'
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "Defender Block: $action completed (Registry + Services)" -Level Info
        }
    }
    # === KATEGORIE 10: FULL ADMIN (Context Menu) ===
    if ($Category -in @('FullAdmin', 'All')) {
        Write-Host "  -> $action Full Admin Control..." -ForegroundColor Cyan
        $result = Invoke-WithPrivilege -ScriptBlock {
            param($IsApply)
            if ($IsApply) {
                Write-Host "  -> [SYSTEM] Přidávám Full Admin Control do kontextového menu..." -ForegroundColor Gray
                if (-not (Test-Path "HKLM:\SOFTWARE\Classes\*\shell\runas")) {
                    New-Item -Path "HKLM:\SOFTWARE\Classes\*\shell\runas" -Force | Out-Null
                }
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Classes\*\shell\runas" -Name "HasLUAShield" -Value "" -Type String -Force -ErrorAction SilentlyContinue
                Write-Host "  -> [SYSTEM] Full Admin Control přidán" -ForegroundColor Green
            }
            else {
                Write-Host "  -> [SYSTEM] Odstraňuji Full Admin Control..." -ForegroundColor Gray
                Remove-ItemProperty -Path "HKLM:\SOFTWARE\Classes\*\shell\runas" -Name "HasLUAShield" -Force -ErrorAction SilentlyContinue
                Write-Host "  -> [SYSTEM] Full Admin Control odstraněn" -ForegroundColor Green
            }
        } -ArgumentList @($Apply) -RequiredPrivilege 'System'
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "Full Admin Control: $action completed" -Level Info
        }
    }
    # === KATEGORIE 11: OTHER SECURITY SERVICES (VSS, etc.) ===
    if ($Category -in @('OtherServices', 'All')) {
        Write-Host "  -> $action Doplňkové bezpečnostní služby..." -ForegroundColor Gray
        $result = Invoke-WithPrivilege -ScriptBlock {
            param($IsApply)
            $services = @("VSS", "SgrmBroker", "SecurityHealthService")
            if ($IsApply) {
                foreach ($s in $services) {
                    if (Get-Service $s -ErrorAction SilentlyContinue) {
                        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$s" -Name Start -Value 4 -Force -ErrorAction SilentlyContinue
                        Stop-Service $s -Force -ErrorAction SilentlyContinue
                        Write-Host "  -> [SYSTEM] Služba $s zakázána" -ForegroundColor Gray
                    }
                }
                Write-Host "  -> [SYSTEM] Doplňkové služby zakázány" -ForegroundColor Green
            }
            else {
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\VSS" -Name Start -Value 3 -Force -ErrorAction SilentlyContinue
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SgrmBroker" -Name Start -Value 2 -Force -ErrorAction SilentlyContinue
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SecurityHealthService" -Name Start -Value 3 -Force -ErrorAction SilentlyContinue
                Write-Host "  -> [SYSTEM] Doplňkové služby obnoveny" -ForegroundColor Green
            }
        } -ArgumentList @($Apply) -RequiredPrivilege 'System'
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "Other Security Services: $action completed" -Level Info
        }
    }
    # === KATEGORIE 12: TELEMETRY SERVICES ===
    if ($Category -in @('TelemetryServices', 'All')) {
        Write-Host "  -> $action Telemetrické služby..." -ForegroundColor Gray
        $result = Invoke-WithPrivilege -ScriptBlock {
            param($IsApply)
            $services = @("DiagTrack", "dmwappushservice", "DPS", "WerSvc", "WdiSystemHost", "WdiServiceHost")
            if ($IsApply) {
                foreach ($s in $services) {
                    if (Get-Service $s -ErrorAction SilentlyContinue) {
                        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$s" -Name Start -Value 4 -Force -ErrorAction SilentlyContinue
                        Stop-Service $s -Force -ErrorAction SilentlyContinue
                        Write-Host "  -> [SYSTEM] Služba $s zakázána" -ForegroundColor Gray
                    }
                }
                Write-Host "  -> [SYSTEM] Telemetrické služby zakázány" -ForegroundColor Green
            }
            else {
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack" -Name Start -Value 2 -Force -ErrorAction SilentlyContinue; Start-Service "DiagTrack" -ErrorAction SilentlyContinue
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice" -Name Start -Value 2 -Force -ErrorAction SilentlyContinue
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DPS" -Name Start -Value 2 -Force -ErrorAction SilentlyContinue; Start-Service "DPS" -ErrorAction SilentlyContinue
                Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc" -Name Start -Value 3 -Force -ErrorAction SilentlyContinue
                Write-Host "  -> [SYSTEM] Telemetrické služby obnoveny" -ForegroundColor Green
            }
        } -ArgumentList @($Apply) -RequiredPrivilege 'System'
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "Telemetry Services: $action completed" -Level Info
        }
    }
    # === KATEGORIE 13: TIMER RESOLUTION + HPET ===
    if ($Category -in @('TimerResolution', 'All')) {
        Write-Host "  -> $action Timer Resolution + HPET..." -ForegroundColor Cyan
        if ($Apply) {
            Write-Host "  -> Aplikuji Timer Resolution tweaky..." -ForegroundColor Yellow
            # Kontrola PŘED
            Write-Host "  -> Kontroluji současný stav HPET..." -ForegroundColor Gray
            try {
                $bcdBefore = bcdedit.exe /enum "{current}" | Out-String
                if ($bcdBefore -match "useplatformclock\s+Yes") {
                    Write-Host "  -> [PŘED] HPET je ZAPNUTÝ (useplatformclock Yes)" -ForegroundColor Cyan
                }
                else {
                    Write-Host "  -> [PŘED] HPET je VYPNUTÝ" -ForegroundColor Cyan
                }
            }
            catch {
                Write-Warning "  -> Nepodařilo se načíst stav HPET"
            }
            # bcdedit (Admin)
            try {
                bcdedit.exe /deletevalue useplatformclock | Out-Null
                Write-Host "  -> bcdedit příkaz proveden: /deletevalue useplatformclock" -ForegroundColor Green
                Write-Host "  -> HPET vypnut (TSC použit jako systémový timer)" -ForegroundColor Green
            }
            catch {
                Write-Host "  -> bcdedit: useplatformclock již neexistuje" -ForegroundColor Gray
            }
            # Kontrola PO
            Write-Host "  -> Kontroluji stav HPET PO aplikaci..." -ForegroundColor Yellow
            Start-Sleep -Milliseconds 500
            try {
                $bcdAfter = bcdedit.exe /enum "{current}" | Out-String
                if ($bcdAfter -notmatch "useplatformclock\s+Yes") {
                    Write-Host "  -> ✅ [PO] HPET úspěšně VYPNUT" -ForegroundColor Green
                    Write-Host "  -> ✅ TSC bude použit jako systémový timer po restartu" -ForegroundColor Green
                }
                else {
                    Write-Warning "  -> ⚠️  HPET stále zapnutý!"
                }
            }
            catch {
                Write-Warning "  -> Nepodařilo se ověřit stav HPET"
            }
            Write-Host ""
            Write-Warning "⚠️  UPOZORNĚNÍ:"
            Write-Host "  • Timer Resolution je KONTROVERZNÍ tweak!" -ForegroundColor Yellow
            Write-Host "  • Může snížit latenci, ale zvýší spotřebu CPU!" -ForegroundColor Yellow
            Write-Host "  • Doporučeno jen pro high-end desktop PC" -ForegroundColor Yellow
            Write-Host "  • NEDOPORUČENO pro notebooky (vyšší spotřeba)" -ForegroundColor Red
            Write-Host ""
        }
        else {
            # Restore
            Write-Host "  -> Obnovuji Timer Resolution..." -ForegroundColor Cyan
            # Kontrola PŘED
            Write-Host "  -> Kontroluji současný stav HPET..." -ForegroundColor Gray
            try {
                $bcdBefore = bcdedit.exe /enum "{current}" | Out-String
                if ($bcdBefore -match "useplatformclock\s+Yes") {
                    Write-Host "  -> [PŘED] HPET je již ZAPNUTÝ" -ForegroundColor Green
                }
                else {
                    Write-Host "  -> [PŘED] HPET je VYPNUTÝ" -ForegroundColor Cyan
                }
            }
            catch {
                Write-Warning "  -> Nepodařilo se načíst stav HPET"
            }
            # bcdedit (Admin)
            try {
                bcdedit.exe /set useplatformclock true | Out-Null
                Write-Host "  -> bcdedit příkaz proveden: /set useplatformclock true" -ForegroundColor Green
                Write-Host "  -> HPET obnoven" -ForegroundColor Green
            }
            catch {
                Write-Warning "  -> bcdedit příkaz selhal: $($_.Exception.Message)"
            }
            # Kontrola PO
            Write-Host "  -> Kontroluji stav HPET PO obnovení..." -ForegroundColor Yellow
            Start-Sleep -Milliseconds 500
            try {
                $bcdAfter = bcdedit.exe /enum "{current}" | Out-String
                if ($bcdAfter -match "useplatformclock\s+Yes") {
                    Write-Host "  -> ✅ [PO] HPET úspěšně ZAPNUT" -ForegroundColor Green
                }
                else {
                    Write-Warning "  -> ⚠️  HPET nebyl obnoven!"
                }
            }
            catch {
                Write-Warning "  -> Nepodařilo se ověřit stav HPET"
            }
        }
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "Timer Resolution: $action completed (bcdedit HPET)" -Level Info
        }
    }
}
# ═══════════════════════════════════════════════════════════════════════════
# HELPER: Live Timer Resolution Status Check
# ═══════════════════════════════════════════════════════════════════════════
<#
.SYNOPSIS
    Get live Timer Resolution status using NtQueryTimerResolution.
.DESCRIPTION
    Calls Windows API to get current, minimum, and maximum timer resolution.
    Requires P/Invoke .NET code.
.NOTES
#>
function Get-LiveTimerResolution {
    [CmdletBinding()]
    param()
    try {
        # P/Invoke NtQueryTimerResolution
        $signature = @'
[DllImport("ntdll.dll", SetLastError = true)]
public static extern int NtQueryTimerResolution(out uint MinimumResolution, out uint MaximumResolution, out uint CurrentResolution);
'@
        if (-not ([System.Management.Automation.PSTypeName]'NtDll').Type) {
            Add-Type -MemberDefinition $signature -Name "NtDll" -Namespace "Win32"
        }
        [uint]$min = 0
        [uint]$max = 0
        [uint]$current = 0
        $result = [Win32.NtDll]::NtQueryTimerResolution([ref]$min, [ref]$max, [ref]$current)
        if ($result -eq 0) {
            # Convert 100ns units to ms
            $currentMs = [math]::Round($current / 10000.0, 2)
            $minMs = [math]::Round($min / 10000.0, 2)
            $maxMs = [math]::Round($max / 10000.0, 2)
            return @{
                Success      = $true
                CurrentMs    = $currentMs
                MinMs        = $minMs
                MaxMs        = $maxMs
                Current100ns = $current
            }
        }
        else {
            return @{ Success = $false; Error = "NtQueryTimerResolution failed (NTSTATUS: 0x$($result.ToString('X8')))" }
        }
    }
    catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}
# ═══════════════════════════════════════════════════════════════════════════
# HELPER: Show Timer Resolution Info Menu
# ═══════════════════════════════════════════════════════════════════════════
<#
.SYNOPSIS
    Show Timer Resolution submenu: [A] Apply, [R] Revert, [I] Info, [Q] Quit.
.DESCRIPTION
    Interactive menu for Timer Resolution tweaks with live status check.
.NOTES
    Kontroverzní tweak - může snížit latenci, ale zvýší spotřebu CPU.
#>
function Show-TimerResolutionMenu {
    [CmdletBinding()]
    param()
    while ($true) {
        Clear-Host
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
        Write-Host "   TIMER RESOLUTION + HPET (Kontroverzní Tweak)"              -ForegroundColor Magenta
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
        Write-Host ""
        # Live status check
        Write-Host "═══ 📊 LIVE STATUS ===" -ForegroundColor Cyan
        Write-Host ""
        # bcdedit HPET status
        try {
            $bcdOutput = bcdedit.exe /enum "{current}" | Out-String
            if ($bcdOutput -match "useplatformclock\s+Yes") {
                Write-Host "  • HPET Timer:         ZAPNUTÝ (useplatformclock Yes)" -ForegroundColor Green
            }
            else {
                Write-Host "  • HPET Timer:         VYPNUTÝ (TSC používán)" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "  • HPET Timer:         NELZE ZJISTIT" -ForegroundColor Gray
        }
        # Live resolution via API
        $timerStatus = Get-LiveTimerResolution
        if ($timerStatus.Success) {
            Write-Host "  • Aktuální Resoluce:  $($timerStatus.CurrentMs) ms ($($timerStatus.Current100ns) × 100ns)" -ForegroundColor Cyan
            Write-Host "  • Rozsah:             $($timerStatus.MinMs) ms - $($timerStatus.MaxMs) ms" -ForegroundColor Gray
        }
        else {
            Write-Host "  • Aktuální Resoluce:  NELZE ZJISTIT ($($timerStatus.Error))" -ForegroundColor Gray
        }
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "[A] ⚡ Aplikovat Timer Resolution Tweak (HPET OFF)" -ForegroundColor Green
        Write-Host "    → Vypne HPET, použije TSC pro nižší latenci" -ForegroundColor Gray
        Write-Host "    → RESTART NUTNÝ" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[R] 🔄 Obnovit výchozí nastavení (HPET ON)" -ForegroundColor Yellow
        Write-Host "    → Zapne HPET zpět" -ForegroundColor Gray
        Write-Host "    → RESTART NUTNÝ" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[I] ℹ️  Info o Timer Resolution" -ForegroundColor White
        Write-Host ""
        Write-Host "[Q] ⬅️  Zpět do Security Hazard menu" -ForegroundColor Red
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
        Write-Host ""
        $choice = Read-Host -Prompt "Zadejte svou volbu"
        switch ($choice.ToUpper()) {
            'A' {
                # Apply Timer Resolution
                $pin = Read-Host -Prompt "Pro aplikaci Timer Resolution tweaku zadejte PIN [1337]"
                if ($pin -eq '1337') {
                    Write-Host ""
                    Invoke-SecurityTweaks -Category 'TimerResolution' -Apply
                    Write-Host ""
                    Write-Warning "⚠️  RESTART NUTNÝ pro aplikaci změn!"
                    Write-Host ""
                    Write-Host "Stiskněte Enter pro pokračování..." ; $null = Read-Host
                }
                else {
                    Write-Error "Nesprávný PIN. Operace zrušena."
                    Start-Sleep -Seconds 2
                }
            }
            'R' {
                # Revert Timer Resolution
                $confirm = Read-Host -Prompt "Opravdu chcete obnovit výchozí nastavení? (Ano/Ne)"
                if ($confirm -match '^a') {
                    Write-Host ""
                    Invoke-SecurityTweaks -Category 'TimerResolution'
                    Write-Host ""
                    Write-Warning "⚠️  RESTART NUTNÝ pro aplikaci změn!"
                    Write-Host ""
                    Write-Host "Stiskněte Enter pro pokračování..." ; $null = Read-Host
                }
                else {
                    Write-Host "Operace zrušena." -ForegroundColor Yellow
                    Start-Sleep -Seconds 2
                }
            }
            'I' {
                # Info
                Clear-Host
                Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
                Write-Host "    ℹ️  INFO O TIMER RESOLUTION + HPET" -ForegroundColor Cyan
                Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Timer Resolution je interval, ve kterém Windows probouzí CPU." -ForegroundColor White
                Write-Host "Výchozí hodnota je ~15.625 ms (64 Hz)." -ForegroundColor White
                Write-Host ""
                Write-Host "Co tento tweak dělá:" -ForegroundColor Yellow
                Write-Host "  • Vypne HPET (High Precision Event Timer)" -ForegroundColor White
                Write-Host "  • Použije TSC (Time Stamp Counter) jako systémový timer" -ForegroundColor White
                Write-Host "  • TSC je rychlejší a má nižší latenci než HPET" -ForegroundColor White
                Write-Host ""
                Write-Host "Přínosy:" -ForegroundColor Green
                Write-Host "  • Nižší input lag (1-3 ms zlepšení)" -ForegroundColor White
                Write-Host "  • Rychlejší response time pro časově citlivé aplikace" -ForegroundColor White
                Write-Host "  • Lepší frame pacing ve hrách" -ForegroundColor White
                Write-Host ""
                Write-Host "Rizika:" -ForegroundColor Red
                Write-Host "  • Vyšší spotřeba CPU (~5-10% idle)" -ForegroundColor White
                Write-Host "  • Vyšší teploty na noteboocích" -ForegroundColor White
                Write-Host "  • Kratší výdrž baterie (notebooky)" -ForegroundColor White
                Write-Host "  • NEDOPORUČENO pro notebooky nebo úsporné PC!" -ForegroundColor Red
                Write-Host ""
                Write-Host "⚠️  DOPORUČENÍ:" -ForegroundColor Yellow
                Write-Host "  • Pouze pro high-end desktop PC s dobrou ventilací" -ForegroundColor White
                Write-Host "  • Pro kompetitivní esport hráče" -ForegroundColor White
                Write-Host "  • Sledujte teploty CPU (HWiNFO, MSI Afterburner)" -ForegroundColor White
                Write-Host ""
                Write-Host "💡 TIP: Vyzkoušejte s/bez tweaku a změřte rozdíl!" -ForegroundColor Cyan
                Write-Host "       (LatencyMon, DPC Latency Checker, InGame FPS meter)" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Stiskněte Enter pro návrat do menu..." ; $null = Read-Host
            }
            'Q' { return }
            default {
                Write-Warning "Neplatná volba. Zkuste to znovu."
                Start-Sleep -Seconds 2
            }
        }
    }
}
# ═══════════════════════════════════════════════════════════════════════════
# HOSTS TELEMETRY MANAGEMENT - BLOKACE TELEMETRIE PRES HOSTS FILE
# ═══════════════════════════════════════════════════════════════════════════
<#
.SYNOPSIS
    Block telemetry domains via HOSTS file and firewall.
.DESCRIPTION
    Adds ~40 telemetry domains to HOSTS file (0.0.0.0 mapping)
    and creates firewall rule to block telemetry IPs.
    ⚠️  WARNING: May affect Windows Update and other services!
    ⚠️  ANTIVIRUS FALSE POSITIVE: Your AV may flag this as suspicious!
.NOTES
    Based on KRAKE-FIX-v1.ps1 Invoke-HostsTelemetryBlock
    Creates backup at: C:\Windows\System32\drivers\etc\hosts.backup
#>
function Invoke-HostsTelemetryBlock {
    [CmdletBinding()]
    param()
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Red
    Write-Host "          HOSTS TELEMETRY BLOCK (RIZIKOVE!)" -ForegroundColor Red
    Write-Host "============================================================================" -ForegroundColor Red
    Write-Host ""
    Write-Warning "Tato funkce blokuje telemetricke domeny pres HOSTS file a firewall!"
    Write-Host ""
    Write-Host "Provede se:" -ForegroundColor Yellow
    Write-Host "  1. Pridani ~40 telemetrickych domen do HOSTS file" -ForegroundColor Gray
    Write-Host "  2. Vytvoreni firewall pravidla pro blokovani telemetrických IP" -ForegroundColor Gray
    Write-Host ""
    Write-Host "VAROVANI: Muze ovlivnit Windows Update a dalsi funkce!" -ForegroundColor Red
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "UPOZORNENI - ANTIVIRUS FALSE POSITIVE!" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "Tvuj antivirus muze FALESNE ohlasit tuto akci jako nebezpecnou!" -ForegroundColor Cyan
    Write-Host "Duvod: Blokovani 40+ Microsoft domen v HOSTS file" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Toto je LEGITIMNI akce - pouze blokuje telemetrii!" -ForegroundColor Green
    Write-Host "Pokud antivirus oznami 'hrozbu', pridej tuto aplikaci do vyjimek." -ForegroundColor Gray
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Pokracovat? (Y/N)" -ForegroundColor Yellow
    $confirm = Read-Host
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Host "Operace zrusena." -ForegroundColor Gray
        Start-Sleep -Seconds 1
        return
    }
    try {
        $hosts_file = "$env:systemroot\System32\drivers\etc\hosts"
        # Overit ze HOSTS file existuje, pokud ne, vytvorit ho
        if (-not (Test-Path $hosts_file)) {
            Write-Host "HOSTS file neexistuje, vytvarim novy..." -ForegroundColor Yellow
            $hostsDir = Split-Path $hosts_file -Parent
            if (-not (Test-Path $hostsDir)) {
                New-Item -Path $hostsDir -ItemType Directory -Force | Out-Null
            }
            "# Copyright (c) 1993-2009 Microsoft Corp." | Out-File -FilePath $hosts_file -Encoding ASCII -Force
            "" | Out-File -FilePath $hosts_file -Encoding ASCII -Append
            "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows." | Out-File -FilePath $hosts_file -Encoding ASCII -Append
            "" | Out-File -FilePath $hosts_file -Encoding ASCII -Append
            "127.0.0.1       localhost" | Out-File -FilePath $hosts_file -Encoding ASCII -Append
            "::1             localhost" | Out-File -FilePath $hosts_file -Encoding ASCII -Append
            Write-Host "HOSTS file vytvoren: $hosts_file" -ForegroundColor Green
        }
        # Vytvorit zalohu HOSTS file
        $backup_file = "$env:systemroot\System32\drivers\etc\hosts.backup"
        if (-not (Test-Path $backup_file)) {
            try {
                Copy-Item -Path $hosts_file -Destination $backup_file -Force -ErrorAction Stop
                Write-Host "Zaloha HOSTS file vytvorena: $backup_file" -ForegroundColor Green
            }
            catch {
                Write-Warning "Nepodarilo se vytvorit zalohu: $($_.Exception.Message)"
            }
        }
        # Telemetricke domeny
        $domains = @(
            "a-msedge.net"
            "activity.windows.com"
            "ad.doubleclick.net"
            "bingads.microsoft.com"
            "c.msn.com"
            "cdn.optimizely.com"
            "choice.microsoft.com"
            "compatexchange.cloudapp.net"
            "corp.sts.microsoft.com"
            "diagnostics.support.microsoft.com"
            "feedback.microsoft-hohm.com"
            "feedback.search.microsoft.com"
            "feedback.windows.com"
            "flex.msn.com"
            "g.msn.com"
            "oca.telemetry.microsoft.com"
            "pre.footprintpredict.com"
            "rad.msn.com"
            "redir.metaservices.microsoft.com"
            "schemas.microsoft.akadns.net"
            "settings-win.data.microsoft.com"
            "sls.update.microsoft.com.akadns.net"
            "sqm.df.telemetry.microsoft.com"
            "sqm.telemetry.microsoft.com"
            "statsfe1.ws.microsoft.com"
            "statsfe2.update.microsoft.com.akadns.net"
            "statsfe2.ws.microsoft.com"
            "survey.watson.microsoft.com"
            "telecommand.telemetry.microsoft.com"
            "telemetry.appex.bing.net"
            "telemetry.microsoft.com"
            "telemetry.urs.microsoft.com"
            "vortex-bn2.metron.live.com.nsatc.net"
            "vortex-cy2.metron.live.com.nsatc.net"
            "vortex.data.microsoft.com"
            "vortex-win.data.microsoft.com"
            "watson.microsoft.com"
            "watson.ppe.telemetry.microsoft.com"
            "watson.telemetry.microsoft.com"
            "wes.df.telemetry.microsoft.com"
        )
        Write-Host ""
        Write-Host "Pridavam domeny do HOSTS file..." -ForegroundColor Yellow
        # Nacist HOSTS file do pameti (retry logika pro file locking)
        $hostsContent = $null
        $retryCount = 0
        $maxRetries = 3
        while ($retryCount -lt $maxRetries -and $null -eq $hostsContent) {
            try {
                $hostsContent = Get-Content $hosts_file -ErrorAction Stop
                break
            }
            catch {
                $retryCount++
                if ($retryCount -lt $maxRetries) {
                    Write-Host "Pokus $retryCount/$maxRetries - cekam na pristup k HOSTS file..." -ForegroundColor Yellow
                    Start-Sleep -Milliseconds 500
                }
                else {
                    throw "Nepodarilo se nacist HOSTS file po $maxRetries pokusech: $($_.Exception.Message)"
                }
            }
        }
        # Kontrola zda uz existuje TELEMETRY BLOCK
        $hasBlock = $false
        foreach ($line in $hostsContent) {
            if ($line -match "# === TELEMETRY BLOCK START ===") {
                $hasBlock = $true
                break
            }
        }
        if ($hasBlock) {
            Write-Host "TELEMETRY BLOCK uz existuje v HOSTS file! Preskakuji..." -ForegroundColor Yellow
            Write-Host "Pro novou aplikaci pouzijte nejdrive Restore." -ForegroundColor Cyan
        }
        else {
            # Pripravit novy obsah
            $newContent = @()
            $newContent += $hostsContent
            $newContent += ""
            $newContent += "# === TELEMETRY BLOCK START ==="
            $addedCount = 0
            foreach ($domain in $domains) {
                $newContent += "0.0.0.0 $domain"
                $addedCount++
            }
            $newContent += "# === TELEMETRY BLOCK END ==="
            # Zapsat zpet do HOSTS file (retry logika)
            $retryCount = 0
            $success = $false
            while ($retryCount -lt $maxRetries -and -not $success) {
                try {
                    $newContent | Out-File -FilePath $hosts_file -Encoding ASCII -Force -ErrorAction Stop
                    $success = $true
                    Write-Host "Pridano $addedCount novych domen do HOSTS file" -ForegroundColor Green
                }
                catch {
                    $retryCount++
                    if ($retryCount -lt $maxRetries) {
                        Write-Host "Pokus $retryCount/$maxRetries - cekam na pristup k zapisu..." -ForegroundColor Yellow
                        Start-Sleep -Milliseconds 500
                    }
                    else {
                        throw "Nepodarilo se zapsat do HOSTS file po $maxRetries pokusech: $($_.Exception.Message)"
                    }
                }
            }
        }
        # Firewall pravidla pro blokovani IP
        Write-Host ""
        Write-Host "Vytvarim firewall pravidlo..." -ForegroundColor Yellow
        $ips = @(
            "134.170.30.202"
            "137.116.81.24"
            "157.56.106.189"
            "184.86.53.99"
            "204.79.197.200"
            "23.218.212.69"
            "65.39.117.230"
            "65.55.108.23"
            "64.4.54.254"
        )
        Remove-NetFirewallRule -DisplayName "Block Telemetry IPs" -ErrorAction SilentlyContinue
        New-NetFirewallRule -DisplayName "Block Telemetry IPs" -Direction Outbound -Action Block -RemoteAddress ([string[]]$ips) -ErrorAction Stop | Out-Null
        Write-Host "Firewall pravidlo vytvoreno: Block Telemetry IPs" -ForegroundColor Green
        Write-Host ""
        Write-Host "============================================================================" -ForegroundColor Green
        Write-Host "HOSTS TELEMETRY BLOCK DOKONCEN!" -ForegroundColor Green
        Write-Host "============================================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Zablokovano:" -ForegroundColor Yellow
        Write-Host "  - $($domains.Count) telemetrickych domen" -ForegroundColor White
        Write-Host "  - $($ips.Count) telemetrickych IP adres (firewall)" -ForegroundColor White
        Write-Host ""
        Write-Host "Zaloha HOSTS: $backup_file" -ForegroundColor Gray
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "HOSTS Telemetry Block applied ($($domains.Count) domains, $($ips.Count) IPs)" -Level Warning
        }
    }
    catch {
        Write-Warning "Chyba pri blokovani telemetrie: $($_.Exception.Message)"
    }
    Write-Host ""
    Write-Host "Stiskněte Enter pro pokračování..." ; $null = Read-Host
}
<#
.SYNOPSIS
    Restore HOSTS file from backup (remove telemetry block).
.DESCRIPTION
    Restores HOSTS file from backup or removes TELEMETRY BLOCK section.
    Also removes firewall rule "Block Telemetry IPs".
.NOTES
#>
function Invoke-HostsTelemetryRestore {
    [CmdletBinding()]
    param()
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host "          HOSTS TELEMETRY RESTORE" -ForegroundColor Yellow
    Write-Host "============================================================================" -ForegroundColor Yellow
    Write-Host ""
    try {
        $hosts_file = "$env:systemroot\System32\drivers\etc\hosts"
        $backup_file = "$env:systemroot\System32\drivers\etc\hosts.backup"
        # Overit ze HOSTS file existuje
        if (-not (Test-Path $hosts_file)) {
            Write-Warning "HOSTS file neexistuje! Nelze obnovit."
            Write-Host ""
            Write-Host "Stiskněte Enter pro pokračování..." ; $null = Read-Host
            return
        }
        if (Test-Path $backup_file) {
            Write-Host "Obnovuji HOSTS file ze zalohy..." -ForegroundColor Yellow
            try {
                Copy-Item -Path $backup_file -Destination $hosts_file -Force -ErrorAction Stop
                Write-Host "HOSTS file obnoven ze zalohy" -ForegroundColor Green
            }
            catch {
                Write-Warning "Nepodarilo se obnovit ze zalohy: $($_.Exception.Message)"
                Write-Host "Zkousim alternativni metodu (odstraneni TELEMETRY BLOCK)..." -ForegroundColor Yellow
            }
        }
        if (-not (Test-Path $backup_file) -or $?) {
            Write-Host "Odstranuji telemetricke zaznamy z HOSTS file..." -ForegroundColor Yellow
            # Nacist HOSTS file (retry logika)
            $hostsContent = $null
            $retryCount = 0
            $maxRetries = 3
            while ($retryCount -lt $maxRetries -and $null -eq $hostsContent) {
                try {
                    $hostsContent = Get-Content $hosts_file -ErrorAction Stop
                    break
                }
                catch {
                    $retryCount++
                    if ($retryCount -lt $maxRetries) {
                        Write-Host "Pokus $retryCount/$maxRetries - cekam na pristup k HOSTS file..." -ForegroundColor Yellow
                        Start-Sleep -Milliseconds 500
                    }
                    else {
                        throw "Nepodarilo se nacist HOSTS file po $maxRetries pokusech"
                    }
                }
            }
            $newContent = @()
            $inBlockSection = $false
            $removedCount = 0
            foreach ($line in $hostsContent) {
                if ($line -match "# === TELEMETRY BLOCK START ===") {
                    $inBlockSection = $true
                    continue
                }
                if ($line -match "# === TELEMETRY BLOCK END ===") {
                    $inBlockSection = $false
                    continue
                }
                if (-not $inBlockSection) {
                    $newContent += $line
                }
                else {
                    $removedCount++
                }
            }
            # Zapsat zpet (retry logika)
            $retryCount = 0
            $success = $false
            while ($retryCount -lt $maxRetries -and -not $success) {
                try {
                    $newContent | Out-File -FilePath $hosts_file -Encoding ASCII -Force -ErrorAction Stop
                    $success = $true
                    Write-Host "Odstraneno $removedCount telemetrickych zaznamu" -ForegroundColor Green
                }
                catch {
                    $retryCount++
                    if ($retryCount -lt $maxRetries) {
                        Write-Host "Pokus $retryCount/$maxRetries - cekam na pristup k zapisu..." -ForegroundColor Yellow
                        Start-Sleep -Milliseconds 500
                    }
                    else {
                        throw "Nepodarilo se zapsat do HOSTS file po $maxRetries pokusech"
                    }
                }
            }
        }
        # Odstranit firewall pravidlo
        Write-Host ""
        Write-Host "Odstranuji firewall pravidlo..." -ForegroundColor Yellow
        Remove-NetFirewallRule -DisplayName "Block Telemetry IPs" -ErrorAction SilentlyContinue
        Write-Host "Firewall pravidlo odstraneno" -ForegroundColor Green
        Write-Host ""
        Write-Host "============================================================================" -ForegroundColor Green
        Write-Host "HOSTS file obnoven do puvodniho stavu!" -ForegroundColor Green
        Write-Host "============================================================================" -ForegroundColor Green
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "HOSTS Telemetry Restore completed" -Level Info
        }
    }
    catch {
        Write-Warning "Chyba pri obnoveni HOSTS: $($_.Exception.Message)"
    }
    Write-Host ""
    Write-Host "Stiskněte Enter pro pokračování..." ; $null = Read-Host
}
# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════
<#
.SYNOPSIS
    Interactive menu for security hazard tweaks (RISKY!).
.DESCRIPTION
    Displays menu with 12 security tweaks that REDUCE system security
    for performance/gaming purposes:
    [1]  CPU Mitigations OFF (Spectre/Meltdown)
    [2.1] Windows Update Services BLOCK
    [2.2] Windows Update Drivers BLOCK (registry)
    [3]  VBS & Hyper-V OFF
    [4]  Core Isolation & HVCI OFF
    [5]  LSA Protection OFF
    [6]  Intel TSX OFF
    [7.1] MS Defender Real-Time OFF
    [7.2] MS Defender BLOCK (Registry+Services)
    [8]  Full Admin Control (context menu)
    [9]  Additional Security Services OFF (VSS, etc.)
    [10] Telemetry Services OFF
    [11] HOSTS Telemetry Block
    [12] HOSTS Telemetry Restore
    [R]  Restore ALL security tweaks from backup
    [Q]  Quit
.NOTES
    ⚠️  VAROVÁNÍ: Requires password 'extreme' for entry
    ⚠️  VAROVÁNÍ: Each operation requires PIN confirmation
#>
function Show-SecurityHazardMenu {
    [CmdletBinding()]
    param()
    Clear-Host
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "         MENU PRO RIZIKOVÉ TWEAKY (SECURITY HAZARD)           " -ForegroundColor Magenta
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Warning "⚠️  VAROVÁNÍ: Změny v této sekci mohou ohrozit stabilitu a bezpečnost systému!"
    Write-Host ""
    # Password protection
    $password = Read-Host -Prompt "Pro vstup zadejte autorizační heslo (extreme) nebo [Q] pro návrat"
    if ($password -eq 'Q' -or $password -eq 'q') {
        return
    }
    if ($password -ne 'extreme') {
        Write-Error "Nesprávné heslo. Přístup odepřen."
        Start-Sleep -Seconds 2
        return
    }
    Write-Host ""
    Write-Host "✅ Heslo správné. Vstup povolen." -ForegroundColor Green
    Start-Sleep -Seconds 1
    while ($true) {
        Clear-Host
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
        Write-Host "                RIZIKOVÉ TWEAKY (SECURITY HAZARD)             " -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "⚠️  Každá volba vyžaduje potvrzení PINem." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[1]   Aplikovat tweaky pro MITIGACE CPU (Spectre/Meltdown)" -ForegroundColor Gray
        Write-Host "[2.1] Aplikovat WINDOWS UPDATE služby (blokace služeb)" -ForegroundColor Gray
        Write-Host "[2.2] Aplikovat WINDOWS UPDATE ovladače (blokace přes registry)" -ForegroundColor Gray
        Write-Host "[3]   Aplikovat tweaky pro VBS & HYPER-V (vypnutí virtualizace)" -ForegroundColor Gray
        Write-Host "[4]   Integrita Jádra (Core Isolation & HVCI)" -ForegroundColor Gray
        Write-Host "[5]   Aplikovat tweaky pro LSA (vypnutí ochrany)" -ForegroundColor Gray
        Write-Host "[6]   Aplikovat tweaky pro TSX (vypnutí Intel TSX)" -ForegroundColor Gray
        Write-Host "[7.1] Aplikovat tweaky pro MS DEFENDER (vypnutí Real-time)" -ForegroundColor Red
        Write-Host "[7.2] Aplikovat tweaky pro MS DEFENDER (BLOKACE - Registry+Služby)" -ForegroundColor Red
        Write-Host "[8]   Aplikovat 'Full Admin Control' do kontextového menu" -ForegroundColor Gray
        Write-Host "[9]   Zakázat doplňkové bezpečnostní služby (VSS, atd.)" -ForegroundColor Gray
        Write-Host "[10]  Zakázat telemetrické služby" -ForegroundColor Red
        Write-Host "[11]  HOSTS Telemetry Block (Blokace přes HOSTS file + Firewall)" -ForegroundColor Red
        Write-Host "[12]  HOSTS Telemetry Restore (Obnovení HOSTS file)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor Cyan
        Write-Host "[T]   ⏱️  Timer Resolution + HPET (Kontroverzní tweak)" -ForegroundColor Magenta
        Write-Host "      → Live status, Apply/Revert, Info submenu" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[B]   📋 BCDedit Info (Kompletní informace o boot konfiguraci)" -ForegroundColor Cyan
        Write-Host "      → Zobrazí Secure Boot, HVCI, Hypervisor a další nastavení" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[R]   Obnovit VŠECHNY rizikové tweaky ze zálohy" -ForegroundColor Yellow
        Write-Host "[Q]   Zpět do hlavního menu" -ForegroundColor Red
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
        Write-Host ""
        $choice = Read-Host -Prompt "Zadejte svou volbu"
        $category = $null
        $pin = $null
        $pinPrompt = ""
        switch ($choice) {
            '1' { $category = 'MitigationsCPU'; $pin = '1111'; $pinPrompt = "MITIGACE CPU" }
            '2.1' { 
                # Windows Update služby
                $enteredPin = Read-Host -Prompt "Pro aplikaci WINDOWS UPDATE SLUŽBY zadejte PIN [2211]"
                if ($enteredPin -eq '2211') {
                    Write-Host ""
                    Write-Host "═══════════════════════════════════════════════════════════════"
                    Write-Host "  APLIKUJI WINDOWS UPDATE SLUŽBY (blokace služeb)"
                    Write-Host "═══════════════════════════════════════════════════════════════"
                    Invoke-SecurityTweaks -Category 'WinUpdateServices' -Apply
                    Write-Host "═══════════════════════════════════════════════════════════════"
                    Write-Host "  DOKONČENO!" -ForegroundColor Green
                    Write-Host "═══════════════════════════════════════════════════════════════"
                    Write-Host ""
                    Write-Host "Stiskněte Enter pro pokračování..." ; $null = Read-Host
                }
                else {
                    Write-Error "Nesprávný PIN. Operace zrušena."
                    Start-Sleep -Seconds 2
                }
                continue
            }
            '2.2' { $category = 'WinUpdateDrivers'; $pin = '2222'; $pinPrompt = "WINDOWS UPDATE OVLADAČE (registry)" }
            '3' { $category = 'VBS'; $pin = '3333'; $pinPrompt = "VBS & HYPER-V" }
            '4' { $category = 'Integrity'; $pin = '4444'; $pinPrompt = "INTEGRITA JÁDRA (Core Isolation & HVCI)" }
            '5' { $category = 'LSA'; $pin = '5555'; $pinPrompt = "LSA" }
            '6' { $category = 'TSX'; $pin = '6666'; $pinPrompt = "TSX" }
            '7.1' { $category = 'DefenderRT'; $pin = '7771'; $pinPrompt = "MS DEFENDER (Real-time)" }
            '7.2' { $category = 'DefenderBlock'; $pin = '7772'; $pinPrompt = "MS DEFENDER (Blokace)" }
            '8' { $category = 'FullAdmin'; $pin = '8888'; $pinPrompt = "FULL ADMIN CONTROL" }
            '9' { $category = 'OtherServices'; $pin = '9999'; $pinPrompt = "DOPLŇKOVÉ SLUŽBY" }
            '10' { $category = 'TelemetryServices'; $pin = '1010'; $pinPrompt = "TELEMETRIE" }
            '11' {
                # HOSTS Telemetry Block
                Write-Host ""
                Write-Host "Spouštím HOSTS TELEMETRY BLOCK..." -ForegroundColor Yellow
                Invoke-HostsTelemetryBlock
                continue
            }
            '12' {
                # HOSTS Telemetry Restore
                Write-Host ""
                Write-Host "Spouštím HOSTS TELEMETRY RESTORE..." -ForegroundColor Yellow
                Invoke-HostsTelemetryRestore
                continue
            }
            'R' {
                # Restore ALL
                Write-Host ""
                Write-Warning "⚠️  Obnovuji VŠECHNY bezpečnostní tweaky ze zálohy!"
                $confirm = Read-Host "Opravdu chcete obnovit VŠE? (Ano/Ne)"
                if ($confirm -match '^a') {
                    Write-Host ""
                    Write-Host "Obnovuji VŠECHNY bezpečnostní tweaky..." -ForegroundColor Yellow
                    Invoke-RevertToDefaults -Category 'MitigationsCPU'
                    Write-Host "Obnovuji Windows Update služby..." -ForegroundColor Gray
                    Invoke-RevertToDefaults -Category 'WinUpdateServices'
                    Write-Host "Obnovuji Windows Update ovladače..." -ForegroundColor Gray
                    Invoke-RevertToDefaults -Category 'WinUpdateDrivers'
                    Invoke-RevertToDefaults -Category 'VBS'
                    Invoke-RevertToDefaults -Category 'Integrity'
                    Invoke-RevertToDefaults -Category 'LSA'
                    Invoke-RevertToDefaults -Category 'TSX'
                    Invoke-RevertToDefaults -Category 'DefenderRT'
                    Invoke-RevertToDefaults -Category 'DefenderBlock'
                    Invoke-RevertToDefaults -Category 'FullAdmin'
                    Invoke-RevertToDefaults -Category 'OtherServices'
                    Invoke-RevertToDefaults -Category 'TelemetryServices'
                    Write-Host ""
                    Write-Host "✅ VŠECHNY bezpečnostní tweaky obnoveny!" -ForegroundColor Green
                    Write-Host "💡 TIP: Restartujte počítač pro aplikaci změn." -ForegroundColor Yellow
                }
                else {
                    Write-Host "Operace zrušena." -ForegroundColor Yellow
                }
                Write-Host ""
                Write-Host "Stiskněte Enter pro pokračování..." ; $null = Read-Host
                continue
            }
            'T' {
                # Timer Resolution submenu
                Show-TimerResolutionMenu
                continue
            }
            'B' {
                # BCDedit Info - kompletní informace o boot konfiguraci
                Clear-Host
                Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
                Write-Host "              📋 BCDEDIT INFO - Boot Configuration            " -ForegroundColor Cyan
                Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
                Write-Host ""
                try {
                    # Zjištění Secure Boot stavu (vyžaduje Admin)
                    Write-Host "🔐 Secure Boot Status:" -ForegroundColor Yellow
                    try {
                        $secureBoot = Confirm-SecureBootUEFI
                        if ($secureBoot) {
                            Write-Host "   ✅ ZAPNUTO (UEFI Secure Boot je aktivní)" -ForegroundColor Green
                        }
                        else {
                            Write-Host "   ❌ VYPNUTO (UEFI Secure Boot není aktivní)" -ForegroundColor Red
                        }
                    }
                    catch {
                        Write-Host "   ℹ️  Nelze zjistit (pravděpodobně Legacy BIOS)" -ForegroundColor Gray
                    }
                    Write-Host ""
                    # Zobrazení klíčových hodnot NEJDŘÍV (před scrollem)
                    Write-Host "🔍 Klíčové hodnoty (current boot entry):" -ForegroundColor Yellow
                    $currentBootRaw = bcdedit.exe /enum "{current}"
                    $currentBoot = $currentBootRaw | Out-String
                    # Hypervisor launch
                    if ($currentBoot -match "hypervisorlaunchtype\s+(.+)") {
                        $hypervisor = $matches[1].Trim()
                        if ($hypervisor -eq "Off") {
                            Write-Host "   🔴 Hypervisor Launch: OFF (VBS vypnut)" -ForegroundColor Red
                        }
                        else {
                            Write-Host "   🟢 Hypervisor Launch: $hypervisor (VBS může běžet)" -ForegroundColor Green
                        }
                    }
                    else {
                        Write-Host "   ℹ️  Hypervisor Launch: Nenalezeno" -ForegroundColor Gray
                    }
                    # No integrity checks
                    if ($currentBoot -match "nointegritychecks\s+Yes") {
                        Write-Host "   🔴 Integrity Checks: DISABLED (HVCI vypnut)" -ForegroundColor Red
                    }
                    else {
                        Write-Host "   🟢 Integrity Checks: ENABLED (HVCI může běžet)" -ForegroundColor Green
                    }
                    # TSX
                    if ($currentBoot -match "tsxenable\s+(.+)") {
                        $tsx = $matches[1].Trim()
                        Write-Host "   ℹ️  TSX: $tsx" -ForegroundColor Cyan
                    }
                    # Debug mode
                    if ($currentBoot -match "debug\s+Yes") {
                        Write-Host "   ⚠️  Debug Mode: ENABLED" -ForegroundColor Yellow
                    }
                    Write-Host ""
                    Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor Gray
                    Write-Host "💡 Pro zobrazení KOMPLETNÍHO BCDedit výpisu stiskněte Enter..." -ForegroundColor Yellow
                    Write-Host "   (nebo [Q] pro návrat do menu)" -ForegroundColor Gray
                    $showFull = Read-Host
                    if ($showFull -ne 'Q' -and $showFull -ne 'q') {
                        Write-Host ""
                        Write-Host "📋 Kompletní BCDedit konfigurace:" -ForegroundColor Yellow
                        Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor Gray
                        $bcdOutput = bcdedit.exe /enum all
                        $bcdOutput | ForEach-Object { Write-Host $_ -ForegroundColor White }
                        Write-Host "──────────────────────────────────────────────────────────────" -ForegroundColor Gray
                        Write-Host ""
                        Write-Host "💡 TIP: Pro změny v BCDedit použijte příslušné tweaky v Security menu" -ForegroundColor Gray
                    }
                }
                catch {
                    Write-Error "Chyba při načítání BCDedit informací: $($_.Exception.Message)"
                }
                Write-Host ""
                Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
                Write-Host "Stiskněte Enter pro návrat do menu..." -ForegroundColor Yellow
                $null = Read-Host
                continue
            }
            'Q' { return }
            default {
                Write-Warning "Neplatná volba. Zkuste to znovu."
                Start-Sleep -Seconds 2
                continue
            }
        }
        # Execute tweak s PIN potvrzením
        if ($null -ne $category) {
            $enteredPin = Read-Host -Prompt "Pro aplikaci '$pinPrompt' zadejte PIN [$pin]"
            if ($enteredPin -eq $pin) {
                Write-Host ""
                Write-Host "═══════════════════════════════════════════════════════════════"
                Write-Host "  APLIKUJI: $pinPrompt"
                Write-Host "═══════════════════════════════════════════════════════════════"
                Invoke-RevertToDefaults -Category $category -Apply
                Write-Host "═══════════════════════════════════════════════════════════════"
                Write-Host "  DOKONČENO!" -ForegroundColor Green
                Write-Host "═══════════════════════════════════════════════════════════════"
                if ($category -in @('VBS', 'Integrity', 'MitigationsCPU', 'LSA', 'TSX', 'TimerResolution')) {
                    Write-Host ""
                    Write-Warning "⚠️  RESTART NUTNÝ pro aplikaci změn!"
                }
            }
            else {
                Write-Error "Nesprávný PIN. Operace zrušena."
            }
        }
        Write-Host ""
        Write-Host "Stiskněte klávesu pro pokračování..." ; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
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
    Show-SecurityHazardMenu
}
Export-ModuleMember -Function @(
    'Show-SecurityHazardMenu',
    'Show-TimerResolutionMenu',
    'Get-LiveTimerResolution',
    'Invoke-RevertToDefaults',
    'Invoke-HostsTelemetryBlock',
    'Invoke-HostsTelemetryRestore',
    'Invoke-ModuleEntry'
)
# ═══════════════════════════════════════════════════════════════════════════
# MODULE INITIALIZATION LOG
# ═══════════════════════════════════════════════════════════════════════════
if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
    Write-CoreLog -Message "Security.psm1 v$script:ModuleVersion loaded successfully" -Level Info
}