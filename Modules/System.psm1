# ═══════════════════════════════════════════════════════════════════════════

# Module: System.psm1

# ═══════════════════════════════════════════════════════════════════════════

# Project:      KRAKE-FIX v2 Modular

# Version:      2.0.1

# Author:       KRAKE-FIX Team

# Created:      2025-10-29

# Last Updated: 2025-10-30

# ═══════════════════════════════════════════════════════════════════════════

# Description:  System tweaks - Win32Priority, HID optimizations, LargeSystemCache, Gaming Performance

# Category:     System

# Dependencies: Core.psm1

# Admin Rights: Required

# ═══════════════════════════════════════════════════════════════════════════

# ⚠️  SECURITY & COMPLIANCE NOTICE

# ═══════════════════════════════════════════════════════════════════════════

# • This module modifies system configuration

# • Designed for educational and testing purposes only

# • Author assumes no liability for misuse outside academic context

# • Always create system restore point before use

# • BSI4 compliant: Input validation, error handling, audit logging

# ═══════════════════════════════════════════════════════════════════════════



#Requires -Version 5.1

#Requires -RunAsAdministrator



using namespace System.Management.Automation



# ───────────────────────────────────────────────────────────────────────────

# IMPORT CORE MODULE

# ───────────────────────────────────────────────────────────────────────────



# Import Core modulu pro privilege management (Invoke-RegistryOperation, Write-CoreLog)
# Use Core module functions - loaded by Main.ps1, only import if standalone
if (-not (Get-Command Write-CoreLog -ErrorAction SilentlyContinue)) {
    $CoreModule = Join-Path $PSScriptRoot 'Core.psm1'
    if (Test-Path $CoreModule) {
        Import-Module $CoreModule -Force -ErrorAction Stop
    } else {
        Write-Warning "Core.psm1 not found - some functionality unavailable"
    }
}



# ───────────────────────────────────────────────────────────────────────────

# MODULE INITIALIZATION

# ───────────────────────────────────────────────────────────────────────────



Set-StrictMode -Version Latest

$ErrorActionPreference = 'Stop'



# Module-level variables (private)

$script:ModuleName = 'System'

$script:ModuleVersion = '2.0.1'

$script:LogPath = Join-Path $env:TEMP "KRAKE-FIX-$script:ModuleName.log"



# ───────────────────────────────────────────────────────────────────────────

# HELPER FUNCTIONS

# ───────────────────────────────────────────────────────────────────────────

# NOTE: Write-CoreLog is provided by Core.psm1 (imported above)

# ───────────────────────────────────────────────────────────────────────────

# HELPER FUNCTION (BSI4 Optimized - Uses Invoke-RegistryOperation from Core.psm1)
function Set-RegistryValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [object]$Value,

        [ValidateSet('String', 'DWord', 'QWord', 'Binary', 'ExpandString', 'MultiString')]
        [string]$Type = 'DWord',

        [switch]$CreatePath
    )

    try {
        # Direct registry write (bypassing Core's Invoke-RegistryOperation due to parameter issues)
        # Create path if needed
        if ($CreatePath -and -not (Test-Path -LiteralPath $Path)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
            Write-Verbose "Created registry path: $Path"
        }

        # Ensure proper type conversion for DWord/QWord
        $converted = switch ($Type) {
            'DWord' { [int]$Value }
            'QWord' { [long]$Value }
            default { $Value }
        }

        # Check if property exists
        $propertyExists = $false
        if (Test-Path -LiteralPath $Path) {
            try {
                $existing = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
                if ($null -ne $existing) {
                    $propertyExists = $true
                }
            }
            catch {
                $propertyExists = $false
            }
        }

        # Set or create property
        if ($propertyExists) {
            Set-ItemProperty -LiteralPath $Path -Name $Name -Value $converted -Force -ErrorAction Stop
            Write-Verbose "Registry updated: $Path\$Name = $converted (Type: $Type)"
        }
        else {
            New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType $Type -Value $converted -Force -ErrorAction Stop | Out-Null
            Write-Verbose "Registry created: $Path\$Name = $converted (Type: $Type)"
        }

        return $true
    }
    catch {
        Write-Warning "Registry operation failed for $Path\$Name : $($_.Exception.Message)"
        return $false
    }
}

# ───────────────────────────────────────────────────────────────────────────

# SYSTEM TWEAK FUNCTIONS

# ───────────────────────────────────────────────────────────────────────────

# [3] Win32PrioritySeparation Menu
# [4] HID Latence Menu (Keyboard/Mouse)
# [5] LargeSystemCache Menu
# [10] Gaming Performance Tweaks Menu

# ═══════════════════════════════════════════════════════════════════════════
# [4] HID LATENCE (KLÁVESNICE/MYŠ)
# ═══════════════════════════════════════════════════════════════════════════

function Show-HidMenu {
    while ($true) {
        Clear-Host
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host "           H.I.D. TWEAK MENU (Latence Vstupu)                 " -ForegroundColor Green
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""

        # ── ČTENÍ AKTUÁLNÍCH HODNOT Z REGISTRY ─────────────────────
        $KbdPath = "HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters"
        $MousePath = "HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters"
        $CurrentKbd = 100  # Výchozí hodnota
        $CurrentMouse = 100  # Výchozí hodnota

        try {
            if (Test-Path -Path $KbdPath) {
                $val = (Get-ItemProperty -Path $KbdPath -Name "KeyboardDataQueueSize" -ErrorAction SilentlyContinue).'KeyboardDataQueueSize'
                if ($null -ne $val) { $CurrentKbd = $val }
            }
        } catch {
            Write-Warning "Nepodařilo se přečíst aktuální hodnotu KeyboardDataQueueSize"
        }

        try {
            if (Test-Path -Path $MousePath) {
                $val = (Get-ItemProperty -Path $MousePath -Name "MouseDataQueueSize" -ErrorAction SilentlyContinue).'MouseDataQueueSize'
                if ($null -ne $val) { $CurrentMouse = $val }
            }
        } catch {
            Write-Warning "Nepodařilo se přečíst aktuální hodnotu MouseDataQueueSize"
        }

        # ── ZOBRAZENÍ AKTUÁLNÍCH HODNOT ────────────────────────────
        Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  AKTUÁLNÍ NASTAVENÍ" -ForegroundColor Yellow
        Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  Klávesnice: " -NoNewline -ForegroundColor Gray
        Write-Host $CurrentKbd -ForegroundColor Green
        Write-Host "  Myš       : " -NoNewline -ForegroundColor Gray
        Write-Host $CurrentMouse -ForegroundColor Green
        Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  ⚠️  Změny se projeví až po restartu PC / odhlášení!" -ForegroundColor Yellow
        Write-Host ""

        # ── MENU V DVOJITÉM SLOUPCI ────────────────────────────────
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
        Write-Host "  KLÁVESNICE                         MYŠ" -ForegroundColor Yellow
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
        Write-Host "[K1] Experimental: 45             [M1] Experimental: 45" -ForegroundColor Magenta
        Write-Host "[K2] Agresivní: 50                [M2] Agresivní: 50" -ForegroundColor Red
        Write-Host "[K3] Nízká latence: 55            [M3] Nízká latence: 55" -ForegroundColor Cyan
        Write-Host "[K4] Vyvážené: 60                 [M4] Vyvážené: 60" -ForegroundColor Cyan
        Write-Host "[K5] Standardní: 70               [M5] Standardní: 70" -ForegroundColor Cyan
        Write-Host "[K6] Standardní+: 80              [M6] Standardní+: 80" -ForegroundColor Cyan
        Write-Host "[C]  OEM Výchozí: 100             [C]  OEM Výchozí: 100" -ForegroundColor Gray
        Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor White
        Write-Host ""
        Write-Host "[Q] Zpět do hlavního menu" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host -Prompt "Zadejte svou volbu"
        $kbdValue = $null
        $mouseValue = $null

        switch ($choice.ToUpper()) {
            # KLÁVESNICE
            'K1' { $kbdValue = 45 }
            'K2' { $kbdValue = 50 }
            'K3' { $kbdValue = 55 }
            'K4' { $kbdValue = 60 }
            'K5' { $kbdValue = 70 }
            'K6' { $kbdValue = 80 }

            # MYŠ
            'M1' { $mouseValue = 45 }
            'M2' { $mouseValue = 50 }
            'M3' { $mouseValue = 55 }
            'M4' { $mouseValue = 60 }
            'M5' { $mouseValue = 70 }
            'M6' { $mouseValue = 80 }

            # OEM VÝCHOZÍ (obě najednou)
            'C' {
                $kbdValue = 100
                $mouseValue = 100
            }

            # NÁVRAT
            'Q' { return }

            default {
                Write-Warning "Neplatná volba. Použijte K1-K6 pro klávesnici, M1-M6 pro myš, C pro výchozí nebo Q pro návrat."
                Start-Sleep -Seconds 2
            }
        }

        # ── APLIKACE HODNOT (PRIVILEGE WRAPPER) ────────────────────
        if ($null -ne $kbdValue) {
            $success = Set-RegistryValue -Path $KbdPath -Name "KeyboardDataQueueSize" -Value $kbdValue -Type DWord -CreatePath
            if ($success) {
                Write-Host ""
                Write-Host "✅ Klávesnice: KeyboardDataQueueSize nastaveno na $kbdValue" -ForegroundColor Green
            } else {
                Write-Error "❌ Nepodařilo se nastavit hodnotu pro klávesnici"
            }
        }

        if ($null -ne $mouseValue) {
            $success = Set-RegistryValue -Path $MousePath -Name "MouseDataQueueSize" -Value $mouseValue -Type DWord -CreatePath
            if ($success) {
                Write-Host "✅ Myš: MouseDataQueueSize nastaveno na $mouseValue" -ForegroundColor Green
            } else {
                Write-Error "❌ Nepodařilo se nastavit hodnotu pro myš"
            }
        }

        if ($null -ne $kbdValue -or $null -ne $mouseValue) {
            Write-Host ""
            Write-Host "⚠️  Pro projevení změn je nutný RESTART PC nebo ODHLÁŠENÍ!" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Stiskněte klávesu pro pokračování..." -ForegroundColor White
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════
# [5] LARGESYSTEMCACHE OPTIMALIZACE
# ═══════════════════════════════════════════════════════════════════════════

function Show-LargeSystemCacheMenu {
    while ($true) {
        Clear-Host
        Write-Host "==========================================================" -ForegroundColor Magenta
        Write-Host "  Optimalizace LargeSystemCache (Kompilace/Data vs. Hraní)" -ForegroundColor Red
        Write-Host "==========================================================" -ForegroundColor Magenta
        Write-Host "Tato volba mění, jak Windows využívá systémovou cache pro soubory."
        Write-Host "Změna se projeví až po restartu počítače." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Vyberte požadovaný režim:"
        Write-Host "[1] Rychlá Kompilace Shaderů (LargeSystemCache = 1)" -ForegroundColor Cyan
        Write-Host "    -> Použít PŘED spuštěním hry pro kompilaci shaderů (COD, Forza...)."
        Write-Host "    -> VÝSLEDEK: Dramatické zrychlení kompilace (z hodin na minuty)."
        Write-Host "    -> DOPAD: Může způsobit stuttering během hraní." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[2] Plynulé Hraní / FPS (LargeSystemCache = 0)" -ForegroundColor Cyan
        Write-Host "    -> Použít PO dokončení kompilace pro samotné hraní."
        Write-Host "    -> VÝSLEDEK: Plynulý a stabilní frametime bez záseků." -ForegroundColor Green
        Write-Host "    -> DOPAD: Extrémně pomalá kompilace shaderů."
        Write-Host "`n------------------------------------------------------"
        Write-Host "[Q] Zpět do hlavního menu" -ForegroundColor Red

        $choice = Read-Host -Prompt "Zadejte svou volbu"
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
        $keyName = "LargeSystemCache"

        try {
            switch ($choice) {
                '1' {
                    $success = Set-RegistryValue -Path $regPath -Name $keyName -Value 1 -Type DWord -CreatePath
                    if ($success) {
                        Write-Host "ÚSPĚCH: LargeSystemCache nastaveno na '1' (Rychlá Kompilace)." -ForegroundColor Green
                    }
                    break
                }
                '2' {
                    $success = Set-RegistryValue -Path $regPath -Name $keyName -Value 0 -Type DWord -CreatePath
                    if ($success) {
                        Write-Host "ÚSPĚCH: LargeSystemCache nastaveno na '0' (Plynulé Hraní)." -ForegroundColor Green
                    }
                    break
                }
                'q' { return }
                'Q' { return }
                default {
                    Write-Error "Neplatná volba. Zkuste to znovu."
                    Start-Sleep -Seconds 2
                    continue
                }
            }
            Write-Host "Pro projevení změn je NUTNÝ RESTART POČÍTAČE." -ForegroundColor Yellow
            Write-Host "Stiskněte klávesu pro návrat do menu..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

        } catch {
            Write-Error "KRITICKÁ CHYBA: Nepodařilo se zapsat do registru: $($_.Exception.Message)"
            Start-Sleep -Seconds 5
        }
    }
}


# ═══════════════════════════════════════════════════════════════════════════
# [3] WIN32PRIORITYSEPARATION TWEAK MENU
# ═══════════════════════════════════════════════════════════════════════════

function Show-Win32PrioMenu {
    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host "        Win32PrioritySeparation TWEAK MENU        " -ForegroundColor Magenta
        Write-Host "==================================================" -ForegroundColor Green

        # ── ČTENÍ AKTUÁLNÍ HODNOTY Z REGISTRY ──────────────────
        $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl"
        $CurrentValue = 0x02  # Výchozí hodnota

        try {
            if (Test-Path -Path $RegPath) {
                $CurrentValue = (Get-ItemProperty -Path $RegPath -Name "Win32PrioritySeparation" -ErrorAction SilentlyContinue).'Win32PrioritySeparation'
                if ($null -eq $CurrentValue) { $CurrentValue = 0x02 }
            }
        } catch {
            Write-Warning "Nepodařilo se přečíst aktuální hodnotu Win32PrioritySeparation"
        }

        # ── DEKÓDOVÁNÍ HODNOTY ──────────────────────────────────
        # Bit 0-1: Interval (00=Short, 01=Medium, 10=Long)
        # Bit 2:   Variable (0=Fixed, 1=Variable)
        # Bit 3-5: Foreground Boost (0-31)

        $Interval = switch ($CurrentValue -band 0x03) {
            0 { "Short" }
            1 { "Medium" }
            2 { "Long" }
            3 { "Long" }
        }

        $Variable = if (($CurrentValue -band 0x04) -ne 0) { "Variable" } else { "Fixed" }
        $BoostLevel = ($CurrentValue -band 0x38) -shr 3

        # ── ZOBRAZENÍ AKTUÁLNÍ HODNOTY ─────────────────────────
        Write-Host ""
        Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  AKTUÁLNÍ NASTAVENÍ" -ForegroundColor Yellow
        Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  Hodnota (HEX)   : " -NoNewline -ForegroundColor Gray
        Write-Host ("0x{0:X2}" -f $CurrentValue) -ForegroundColor Green
        Write-Host "  Interval        : " -NoNewline -ForegroundColor Gray
        Write-Host $Interval -ForegroundColor White
        Write-Host "  Typ             : " -NoNewline -ForegroundColor Gray
        Write-Host $Variable -ForegroundColor White
        Write-Host "  Foreground Boost: " -NoNewline -ForegroundColor Gray
        Write-Host "$BoostLevel (Multiplier: $($BoostLevel + 1)x)" -ForegroundColor White
        Write-Host "════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""

        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor White
        Write-Host "  VÝBĚR PROFILU Win32PrioritySeparation" -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor White
        Write-Host ""

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # ESPORT / COMPETITIVE (PRIORITA #1)
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        Write-Host "┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Red
        Write-Host "│  🎯 ESPORT / COMPETITIVE (4x-5x) - Nejnižší latence        │" -ForegroundColor Red
        Write-Host "└─────────────────────────────────────────────────────────────┘" -ForegroundColor Red
        Write-Host "[1]  🔥 ULTRA ESPORTS LATENCE (Short, Var, 5x): 0x2A" -ForegroundColor Red
        Write-Host "[2]  ⚡ Agresivní Latence (Short, Var, 4x): 0x24" -ForegroundColor Red
        Write-Host "[3]  🎮 ULTRA GAMING/LATENCE (Long, Var, 4x): 0x26" -ForegroundColor Red
        Write-Host "[4]  💨 Ultra FPS/Latence (Long+1, Var, 4x): 0x27" -ForegroundColor Red
        Write-Host ""

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # GAMING (Vysoký výkon)
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        Write-Host "┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
        Write-Host "│  🎮 GAMING (3x-4x) - Vysoký FPS + stabilita                │" -ForegroundColor Cyan
        Write-Host "└─────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
        Write-Host "[5]  Agresivní FPS/Stabilita (Short+1, Var, 4x): 0x25" -ForegroundColor Cyan
        Write-Host "[6]  Agresivní FPS (Short+1, Var, 4x): 0x23" -ForegroundColor Cyan
        Write-Host "[7]  Gaming/Multitasking (Long, Var, 3x): 0x16" -ForegroundColor Cyan
        Write-Host "[8]  Gaming Balanced (Short, Var, 3x): 0x14" -ForegroundColor Cyan
        Write-Host ""

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # STABILNÍ GAMING (Long Interval - Anti-Stutter)
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        Write-Host "┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Green
        Write-Host "│  ✅ STABILNÍ (Long) - Anti-stutter, plynulé 1% lows        │" -ForegroundColor Green
        Write-Host "└─────────────────────────────────────────────────────────────┘" -ForegroundColor Green
        Write-Host "[9]  Gaming Ultra Stabilní (Long, Var, 5x): 0x22" -ForegroundColor Green
        Write-Host "[10] Gaming Stabilní (Long, Var, 4x): 0x1E" -ForegroundColor Green
        Write-Host ""

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # MULTITASKING (Střední boost)
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        Write-Host "┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
        Write-Host "│  📊 MULTITASKING (2x-3x) - Gaming + práce na pozadí        │" -ForegroundColor Yellow
        Write-Host "└─────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
        Write-Host "[11] FPS Tweak Standard (Short, Fix, 4x): 0x18" -ForegroundColor Yellow
        Write-Host "[12] Vyvážený/Stabilní (Short+1, Var, 2x): 0x13" -ForegroundColor Yellow
        Write-Host "[13] Vyvážený/Legacy FPS (Short+1, Fix, 2x): 0x11" -ForegroundColor Yellow
        Write-Host ""

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # ÚSPORNÉ / LAPTOP / FILMY
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        Write-Host "┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Gray
        Write-Host "│  🔋 LAPTOP / FILMY (1x-2x) - Úspora energie, baterie      │" -ForegroundColor Gray
        Write-Host "└─────────────────────────────────────────────────────────────┘" -ForegroundColor Gray
        Write-Host "[14] Laptop Balanced (Medium, Var, 2x): 0x05" -ForegroundColor Gray
        Write-Host "[15] OEM Výchozí / Filmy (Long, Fix, 1x): 0x02" -ForegroundColor Gray
        Write-Host "[16] Úspora Medium (Medium, Fix, 1x): 0x01" -ForegroundColor Gray
        Write-Host "[17] Úspora Maximum (Short, Fix, 1x): 0x00" -ForegroundColor Gray
        Write-Host ""

        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        # EXTRÉMNÍ TUNING (Experimentální)
        # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        Write-Host "┌─────────────────────────────────────────────────────────────┐" -ForegroundColor Magenta
        Write-Host "│  ⚠️  EXTRÉMNÍ (5x-8x) - Pouze pro pokročilé! RIZIKO!      │" -ForegroundColor Magenta
        Write-Host "└─────────────────────────────────────────────────────────────┘" -ForegroundColor Magenta
        Write-Host "[18] Fixed Maximum (Short, Fix, 8x): 0x38" -ForegroundColor Magenta
        Write-Host "[19] Extreme Tuning (Long, Var, 8x): 0x3A" -ForegroundColor Magenta
        Write-Host "[20] Ultra Boost (Short, Var, 7x): 0x34" -ForegroundColor Magenta
        Write-Host "[21] Extrémní Latence (Long, Var, 7x): 0x36" -ForegroundColor Magenta
        Write-Host "[22] High Multiplier (Short, Var, 5x): 0x28" -ForegroundColor Magenta
        Write-Host "[23] Experimental (Long, Fix, 6x): 0x32" -ForegroundColor Magenta
        Write-Host "[24] Experimental 2 (Long, Fix, 6x): 0x30" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor White
        Write-Host "[Q] Zpět do hlavního menu" -ForegroundColor Red
        Write-Host ""

        $choice = Read-Host -Prompt "Zadejte svou volbu"
        $value = $null

        switch ($choice) {
            # ESPORT / COMPETITIVE
            '1'  { $value = 0x2A }
            '2'  { $value = 0x24 }
            '3'  { $value = 0x26 }
            '4'  { $value = 0x27 }
            # GAMING
            '5'  { $value = 0x25 }
            '6'  { $value = 0x23 }
            '7'  { $value = 0x16 }
            '8'  { $value = 0x14 }
            # STABILNÍ GAMING
            '9'  { $value = 0x22 }
            '10' { $value = 0x1E }
            # MULTITASKING
            '11' { $value = 0x18 }
            '12' { $value = 0x13 }
            '13' { $value = 0x11 }
            # ÚSPORNÉ / LAPTOP / FILMY
            '14' { $value = 0x05 }
            '15' { $value = 0x02 }
            '16' { $value = 0x01 }
            '17' { $value = 0x00 }
            # EXTRÉMNÍ TUNING
            '18' { $value = 0x38 }
            '19' { $value = 0x3A }
            '20' { $value = 0x34 }
            '21' { $value = 0x36 }
            '22' { $value = 0x28 }
            '23' { $value = 0x32 }
            '24' { $value = 0x30 }
            # OVLÁDÁNÍ
            'Q'  { return }
            'q'  { return }
            default { Write-Warning "Neplatná volba. Zadejte číslo 1-24 nebo Q." ; Start-Sleep 2}
        }

        if ($null -ne $value) {
            $success = Set-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value $value -Type DWord -CreatePath
            if ($success) {
                Write-Host "  -> Hodnota Win32PrioritySeparation byla nastavena na '$('0x{0:X2}' -f $value)'." -ForegroundColor Green
            } else {
                Write-Error "  -> Nepodařilo se nastavit hodnotu registru"
            }
            Write-Host "Operace dokončena. Stiskněte klávesu pro pokračování..." ; $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
    }
}

# ───────────────────────────────────────────────────────────────────────────

# MODULE INITIALIZATION COMPLETE

# ───────────────────────────────────────────────────────────────────────────


if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
    Write-CoreLog "System module loaded successfully (v$script:ModuleVersion)" -Level SUCCESS
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

    if ($ModuleContext.ContainsKey('RequestedAction') -and $null -ne $ModuleContext.RequestedAction -and -not [string]::IsNullOrWhiteSpace($ModuleContext.RequestedAction)) {
        switch ($ModuleContext.RequestedAction.ToString().ToLowerInvariant()) {
            'win32priority' { Show-Win32PrioMenu; return }
            'hidlatency'    { Show-HidMenu; return }
            'largesystemcache' { Show-LargeSystemCacheMenu; return }
        }
    }

    while ($true) {
        Clear-Host
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "   SYSTEM TWEAKS" -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "[1] Win32PrioritySeparation" -ForegroundColor White
        Write-Host "[2] HID Latency (Klávesnice/Myš)" -ForegroundColor White
        Write-Host "[3] LargeSystemCache" -ForegroundColor White
        Write-Host "[Q] Zpět" -ForegroundColor Red

        $selection = Read-Host "Zadejte volbu"

        switch ($selection) {
            '1' { Show-Win32PrioMenu }
            '2' { Show-HidMenu }
            '3' { Show-LargeSystemCacheMenu }
            'Q' { return }
            'q' { return }
            default {
                Write-Warning "Neplatná volba. Zvolte 1, 2, 3 nebo Q."
                Start-Sleep -Seconds 2
            }
        }
    }
}

Export-ModuleMember -Function @(
    'Show-Win32PrioMenu',
    'Show-HidMenu',
    'Show-LargeSystemCacheMenu',
    'Invoke-ModuleEntry'
)

