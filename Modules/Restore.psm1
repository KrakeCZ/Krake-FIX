# ═══════════════════════════════════════════════════════════════════════════
# Module: Restore.psm1
# ═══════════════════════════════════════════════════════════════════════════
# Project:      KRAKE-FIX v2 Modular
# Version:      2.0.0
# Author:       KRAKE-FIX Team
# Created:      2025-10-29
# ═══════════════════════════════════════════════════════════════════════════
# Description:  System repair functions (DISM, SFC, CHKDSK)
# Category:     System Repair
# Dependencies: Core.psm1
# Admin Rights: Required
# ═══════════════════════════════════════════════════════════════════════════

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
}

# ───────────────────────────────────────────────────────────────────────────
# MODULE INITIALIZATION
# ───────────────────────────────────────────────────────────────────────────

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ModuleName = 'Restore'
$script:ModuleVersion = '2.0.0'

# ═══════════════════════════════════════════════════════════════════════════
# SYSTEM REPAIR MENU
# ═══════════════════════════════════════════════════════════════════════════

function Show-SystemRepairMenu {
    <#
    .SYNOPSIS
        Interactive menu for system repair operations
    
    .DESCRIPTION
        Provides access to DISM, SFC, and CHKDSK repair tools
    #>
    
    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Red
        Write-Host "       SYSTÉMOVÁ OPRAVA" -ForegroundColor Red
        Write-Host "==================================================" -ForegroundColor Red
        Write-Host ""
        Write-Host "VAROVANI: Tyto operace mohou trvat VELMI dlouho!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Vyberte akci:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[1] DISM Scan (Kontrola obrazu Windows)" -ForegroundColor Cyan
        Write-Host "    - DISM /Online /Cleanup-Image /ScanHealth" -ForegroundColor Gray
        Write-Host "    - Rychlejsi kontrola (~5-10 minut)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[2] DISM Repair (Oprava obrazu Windows)" -ForegroundColor Yellow
        Write-Host "    - DISM /Online /Cleanup-Image /RestoreHealth" -ForegroundColor Gray
        Write-Host "    - Muze trvat 15-30+ minut" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[3] SFC Scan (Kontrola systémových souborů)" -ForegroundColor Cyan
        Write-Host "    - sfc /scannow" -ForegroundColor Gray
        Write-Host "    - Muze trvat 15-30+ minut" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[4] CHKDSK Scan (Kontrola disku)" -ForegroundColor Cyan
        Write-Host "    - chkdsk C: /F /R /X" -ForegroundColor Gray
        Write-Host "    - Vyzaduje restart!" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[5] KOMPLEXNÍ OPRAVA (DISM + SFC)" -ForegroundColor Red
        Write-Host "    - DISM RestoreHealth + SFC /scannow" -ForegroundColor Gray
        Write-Host "    - Muze trvat 30-60+ minut!" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[B] Zpet do hlavniho menu" -ForegroundColor Red
        Write-Host ""
        
        $choice = Read-Host -Prompt "Zadejte svou volbu"
        
        switch ($choice) {
            '1' { Invoke-DISMScan }
            '2' { Invoke-DISMRepair }
            '3' { Invoke-SFCScan }
            '4' { Invoke-CHKDSKScan }
            '5' { Invoke-CompleteSystemRepair }
            'B' { return }
            'b' { return }
            default { 
                Write-Warning "Neplatna volba. Zkuste to znovu."
                Start-Sleep -Seconds 2
            }
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# DISM FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

function Invoke-DISMScan {
    <#
    .SYNOPSIS
        Run DISM ScanHealth check
    
    .DESCRIPTION
        Checks Windows image integrity using DISM /ScanHealth
        Faster check (~5-10 minutes)
    #>
    
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "DISM SCAN - Kontrola obrazu Windows" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Spoustim DISM Scan..." -ForegroundColor Yellow
    Write-Host "Toto muze trvat 5-10 minut..." -ForegroundColor Gray
    Write-Host ""
    
    try {
        $result = Start-Process -FilePath "DISM.exe" -ArgumentList "/Online", "/Cleanup-Image", "/ScanHealth" -Wait -NoNewWindow -PassThru
        
        Write-Host ""
        if ($result.ExitCode -eq 0) {
            Write-Host "DISM Scan dokoncen uspesne!" -ForegroundColor Green
        } else {
            Write-Host "DISM Scan dokoncen s chybami (Exit Code: $($result.ExitCode))" -ForegroundColor Yellow
            Write-Host "Zkuste spustit DISM Repair [2]" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "Chyba pri spousteni DISM: $($_.Exception.Message)"
    }
    
    Write-Host ""
    Write-Host "Stisknete klavesu pro pokracovani..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Invoke-DISMRepair {
    <#
    .SYNOPSIS
        Run DISM RestoreHealth repair
    
    .DESCRIPTION
        Repairs Windows image using DISM /RestoreHealth
        May take 15-30+ minutes
    #>
    
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Yellow
    Write-Host "DISM REPAIR - Oprava obrazu Windows" -ForegroundColor Yellow
    Write-Host "======================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "VAROVANI: Tato operace muze trvat 15-30+ minut!" -ForegroundColor Red
    Write-Host "Pokracovat? (Y/N)" -ForegroundColor Yellow
    $confirm = Read-Host
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Host "Operace zrusena." -ForegroundColor Gray
        Start-Sleep -Seconds 2
        return
    }
    
    Write-Host ""
    Write-Host "Spoustim DISM Repair..." -ForegroundColor Yellow
    Write-Host "Prosim, budte trpelivi..." -ForegroundColor Gray
    Write-Host ""
    
    try {
        $result = Start-Process -FilePath "DISM.exe" -ArgumentList "/Online", "/Cleanup-Image", "/RestoreHealth" -Wait -NoNewWindow -PassThru
        
        Write-Host ""
        if ($result.ExitCode -eq 0) {
            Write-Host "DISM Repair dokoncen uspesne!" -ForegroundColor Green
            Write-Host "Doporucujeme spustit SFC Scan [3]" -ForegroundColor Yellow
        } else {
            Write-Host "DISM Repair dokoncen s chybami (Exit Code: $($result.ExitCode))" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "Chyba pri spousteni DISM: $($_.Exception.Message)"
    }
    
    Write-Host ""
    Write-Host "Stisknete klavesu pro pokracovani..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ═══════════════════════════════════════════════════════════════════════════
# SFC FUNCTION
# ═══════════════════════════════════════════════════════════════════════════

function Invoke-SFCScan {
    <#
    .SYNOPSIS
        Run System File Checker
    
    .DESCRIPTION
        Scans and repairs system files using SFC /scannow
        May take 15-30+ minutes
    #>
    
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host "SFC SCAN - Kontrola systémových souborů" -ForegroundColor Cyan
    Write-Host "======================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Spoustim SFC Scan..." -ForegroundColor Yellow
    Write-Host "Toto muze trvat 15-30+ minut..." -ForegroundColor Gray
    Write-Host ""
    
    try {
        $result = Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -Wait -NoNewWindow -PassThru
        
        Write-Host ""
        if ($result.ExitCode -eq 0) {
            Write-Host "SFC Scan dokoncen uspesne!" -ForegroundColor Green
        } else {
            Write-Host "SFC Scan dokoncen s chybami (Exit Code: $($result.ExitCode))" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "Chyba pri spousteni SFC: $($_.Exception.Message)"
    }
    
    Write-Host ""
    Write-Host "Stisknete klavesu pro pokracovani..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ═══════════════════════════════════════════════════════════════════════════
# CHKDSK FUNCTION
# ═══════════════════════════════════════════════════════════════════════════

function Invoke-CHKDSKScan {
    <#
    .SYNOPSIS
        Schedule CHKDSK for next boot
    
    .DESCRIPTION
        Schedules disk check for next system restart
        REQUIRES RESTART!
    #>
    
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Red
    Write-Host "CHKDSK - Kontrola disku" -ForegroundColor Red
    Write-Host "======================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "VAROVANI: Tato operace vyzaduje RESTART!" -ForegroundColor Red
    Write-Host "CHKDSK bude spusten pri pristim startu systemu." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Pokracovat? (Y/N)" -ForegroundColor Yellow
    $confirm = Read-Host
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Host "Operace zrusena." -ForegroundColor Gray
        Start-Sleep -Seconds 2
        return
    }
    
    Write-Host ""
    Write-Host "Planuji CHKDSK pro dalsi restart..." -ForegroundColor Yellow
    
    try {
        # Schedule CHKDSK for next boot
        $null = Start-Process -FilePath "chkdsk.exe" -ArgumentList "C:", "/F", "/R", "/X" -Wait -NoNewWindow -PassThru
        
        Write-Host ""
        Write-Host "CHKDSK naplánovano pro dalsi restart!" -ForegroundColor Green
        Write-Host "Pri pristim startu systemu bude spusten CHKDSK." -ForegroundColor Yellow
        Write-Host "Tato operace muze trvat 30-60+ minut!" -ForegroundColor Yellow
    }
    catch {
        Write-Warning "Chyba pri planovani CHKDSK: $($_.Exception.Message)"
    }
    
    Write-Host ""
    Write-Host "Stisknete klavesu pro pokracovani..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ═══════════════════════════════════════════════════════════════════════════
# COMPLETE SYSTEM REPAIR
# ═══════════════════════════════════════════════════════════════════════════

function Invoke-CompleteSystemRepair {
    <#
    .SYNOPSIS
        Run complete system repair (DISM + SFC)
    
    .DESCRIPTION
        Performs comprehensive system repair:
        1. DISM /RestoreHealth (repairs Windows image)
        2. SFC /scannow (repairs system files)
        
        May take 30-60+ minutes!
    #>
    
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Red
    Write-Host "KOMPLEXNÍ SYSTÉMOVÁ OPRAVA" -ForegroundColor Red
    Write-Host "======================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "VAROVANI: Tato operace muze trvat 30-60+ MINUT!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Provede se:" -ForegroundColor Yellow
    Write-Host "  1. DISM /Online /Cleanup-Image /RestoreHealth" -ForegroundColor Gray
    Write-Host "  2. SFC /scannow" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Opravdu pokracovat? (Y/N)" -ForegroundColor Yellow
    $confirm = Read-Host
    
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Host "Operace zrusena." -ForegroundColor Gray
        Start-Sleep -Seconds 2
        return
    }
    
    Write-Host ""
    Write-Host "=== KROK 1/2: DISM RestoreHealth ===" -ForegroundColor Cyan
    Write-Host "Spoustim DISM Repair..." -ForegroundColor Yellow
    Write-Host ""
    
    try {
        $dismResult = Start-Process -FilePath "DISM.exe" -ArgumentList "/Online", "/Cleanup-Image", "/RestoreHealth" -Wait -NoNewWindow -PassThru
        
        Write-Host ""
        if ($dismResult.ExitCode -eq 0) {
            Write-Host "DISM Repair dokoncen uspesne!" -ForegroundColor Green
        } else {
            Write-Host "DISM Repair dokoncen s chybami (Exit Code: $($dismResult.ExitCode))" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "Chyba pri spousteni DISM: $($_.Exception.Message)"
    }
    
    Write-Host ""
    Write-Host "=== KROK 2/2: SFC Scan ===" -ForegroundColor Cyan
    Write-Host "Spoustim SFC Scan..." -ForegroundColor Yellow
    Write-Host ""
    
    try {
        $sfcResult = Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -Wait -NoNewWindow -PassThru
        
        Write-Host ""
        if ($sfcResult.ExitCode -eq 0) {
            Write-Host "SFC Scan dokoncen uspesne!" -ForegroundColor Green
        } else {
            Write-Host "SFC Scan dokoncen s chybami (Exit Code: $($sfcResult.ExitCode))" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Warning "Chyba pri spousteni SFC: $($_.Exception.Message)"
    }
    
    Write-Host ""
    Write-Host "======================================" -ForegroundColor Green
    Write-Host "KOMPLEXNÍ OPRAVA DOKONCENA!" -ForegroundColor Green
    Write-Host "======================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Doporucujeme restartovat system." -ForegroundColor Yellow
    
    Write-Host ""
    Write-Host "Stisknete klavesu pro pokracovani..." -ForegroundColor Gray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ───────────────────────────────────────────────────────────────────────────
# MODULE EXPORT
# ───────────────────────────────────────────────────────────────────────────

function Invoke-ModuleEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $ModuleContext
    )

    if ($null -eq $ModuleContext) {
        throw [System.ArgumentNullException]::new('ModuleContext')
    }

    Show-SystemRepairMenu
}

Export-ModuleMember -Function @(
    'Show-SystemRepairMenu',
    'Invoke-DISMScan',
    'Invoke-DISMRepair',
    'Invoke-SFCScan',
    'Invoke-CHKDSKScan',
    'Invoke-CompleteSystemRepair',
    'Invoke-ModuleEntry'
)

if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
    Write-CoreLog "Restore module loaded successfully (v$script:ModuleVersion)" -Level SUCCESS
}
