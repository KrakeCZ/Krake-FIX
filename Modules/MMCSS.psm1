# ═══════════════════════════════════════════════════════════════════════════
# Module: MMCSS.psm1
# ═══════════════════════════════════════════════════════════════════════════
# Project:      KRAKE-FIX
# ═══════════════════════════════════════════════════════════════════════════
# Description:  [17] GAME + AUDIO Priority (MMCSS Profily)
#               - Multimedia Class Scheduler Service profile management
#               - Games, Audio, DisplayPostProcessing profiles
#               - CPU affinity, GPU priority, thread priority
# Category:     Performance / Gaming / MMCSS
# Dependencies: Core.psm1
# Admin Rights: Required (registry modification)
# ═══════════════════════════════════════════════════════════════════════════
# ⚠️  SECURITY & COMPLIANCE NOTICE
# ═══════════════════════════════════════════════════════════════════════════
# • This module modifies MMCSS (Multimedia Class Scheduler Service) profiles.
# • Designed for educational and testing purposes only.
# • Author assumes no liability for misuse outside academic context.
# • Always create system restore point before use.
# ===========================================================
# ⚠️ Tento modul může měnit systémové nastavení.
# Používej pouze ve studijním / testovacím prostředí.
# Autor neručí za zneužití mimo akademické účely.
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
    else {
        Write-Error "CRITICAL: Core.psm1 not found! MMCSS.psm1 requires Core.psm1."
        throw "Missing dependency: Core.psm1"
    }
}
# ───────────────────────────────────────────────────────────────────────────
# MODULE INITIALIZATION
# ───────────────────────────────────────────────────────────────────────────
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$script:ModuleName = 'MMCSS'
$script:ModuleVersion = '2.0.0'
$script:LogPath = Join-Path $env:TEMP "KRAKE-FIX-$script:ModuleName.log"
# MMCSS Registry Paths
$script:GamesPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games'
$script:AudioPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio'
$script:DisplayPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing'
# ═══════════════════════════════════════════════════════════════════════════
# MMCSS PROFILE MANAGEMENT - MAIN MENU
# ═══════════════════════════════════════════════════════════════════════════
function Show-GameAudioPriorityMenu {
    <#
    .SYNOPSIS
        [17] GAME + AUDIO Priority Menu (MMCSS Profily)
    .DESCRIPTION
        Interactive menu pro správu MMCSS (Multimedia Class Scheduler Service) profilů:
        - Games: Priority pro hry a interaktivní aplikace
        - Audio: Priority pro audio aplikace a DAW
        - DisplayPostProcessing: Priority pro DWM a post-processing
        Konfigurace:
        - CPU Affinity (na která jádra běží)
        - GPU Priority (1-8)
        - CPU Thread Priority (1-8)
    .NOTES
        MMCSS je Windows služba, která řídí prioritu multimediálních úloh.
        Registry cesty jsou v HKLM:\SOFTWARE\Microsoft\Windows NT\...
    #>
    [CmdletBinding()]
    param()
    while ($true) {
        Clear-Host
        # Detekce CPU jader
        [int]$TotalCores = 0
        try {
            $TotalCores = [int]$env:NUMBER_OF_PROCESSORS
        }
        catch {
            $TotalCores = 0
        }
        # Header
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host "     GAME + AUDIO PRIORITY MENU (MMCSS Profily)          " -ForegroundColor Green
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
        Write-Host "MMCSS (Multimedia Class Scheduler Service) umožňuje nastavit" -ForegroundColor Gray
        Write-Host "prioritu a afinitu pro multimedia úlohy jako hry a audio." -ForegroundColor Gray
        Write-Host ""
        # System Info
        Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host "  SYSTÉMOVÉ INFORMACE" -ForegroundColor White
        Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host ""
        if ($TotalCores -gt 0) {
            Write-Host "  CPU Jádra: $TotalCores logických procesorů (jádra 0 až $($TotalCores - 1))" -ForegroundColor White
        }
        else {
            Write-Host "  CPU Jádra: Nepodařilo se detekovat" -ForegroundColor Yellow
        }
        Write-Host ""
        # Current Profile Status
        Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host "  AKTUÁLNÍ NASTAVENÍ PROFILŮ" -ForegroundColor White
        Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host ""
        # Games Profile
        try {
            $GamesAffinity = (Get-ItemProperty -LiteralPath $script:GamesPath -Name "Affinity" -ErrorAction SilentlyContinue).Affinity
            $GamesGPU = (Get-ItemProperty -LiteralPath $script:GamesPath -Name "GPU Priority" -ErrorAction SilentlyContinue).'GPU Priority'
            $GamesCPU = (Get-ItemProperty -LiteralPath $script:GamesPath -Name "Priority" -ErrorAction SilentlyContinue).Priority
            $GamesAffinityHex = if ($null -ne $GamesAffinity) { "0x{0:X}" -f $GamesAffinity } else { "?" }
            $GamesGPUStr = if ($null -ne $GamesGPU) { $GamesGPU } else { "?" }
            $GamesCPUStr = if ($null -ne $GamesCPU) { $GamesCPU } else { "?" }
            Write-Host "  [1] GAMES:" -ForegroundColor Cyan
            Write-Host "      Afinita: $GamesAffinityHex  |  GPU: $GamesGPUStr  |  CPU: $GamesCPUStr" -ForegroundColor Gray
        }
        catch {
            Write-Host "  [1] GAMES: Nelze načíst" -ForegroundColor Yellow
        }
        # Audio Profile
        try {
            $AudioAffinity = (Get-ItemProperty -LiteralPath $script:AudioPath -Name "Affinity" -ErrorAction SilentlyContinue).Affinity
            $AudioGPU = (Get-ItemProperty -LiteralPath $script:AudioPath -Name "GPU Priority" -ErrorAction SilentlyContinue).'GPU Priority'
            $AudioCPU = (Get-ItemProperty -LiteralPath $script:AudioPath -Name "Priority" -ErrorAction SilentlyContinue).Priority
            $AudioAffinityHex = if ($null -ne $AudioAffinity) { "0x{0:X}" -f $AudioAffinity } else { "?" }
            $AudioGPUStr = if ($null -ne $AudioGPU) { $AudioGPU } else { "?" }
            $AudioCPUStr = if ($null -ne $AudioCPU) { $AudioCPU } else { "?" }
            Write-Host "  [2] AUDIO:" -ForegroundColor Cyan
            Write-Host "      Afinita: $AudioAffinityHex  |  GPU: $AudioGPUStr  |  CPU: $AudioCPUStr" -ForegroundColor Gray
        }
        catch {
            Write-Host "  [2] AUDIO: Nelze načíst" -ForegroundColor Yellow
        }
        # DisplayPostProcessing Profile
        try {
            $DppAffinity = (Get-ItemProperty -LiteralPath $script:DisplayPath -Name "Affinity" -ErrorAction SilentlyContinue).Affinity
            $DppBgPriority = (Get-ItemProperty -LiteralPath $script:DisplayPath -Name "BackgroundPriority" -ErrorAction SilentlyContinue).BackgroundPriority
            $DppGPU = (Get-ItemProperty -LiteralPath $script:DisplayPath -Name "GPU Priority" -ErrorAction SilentlyContinue).'GPU Priority'
            $DppCPU = (Get-ItemProperty -LiteralPath $script:DisplayPath -Name "Priority" -ErrorAction SilentlyContinue).Priority
            $DppAffinityHex = if ($null -ne $DppAffinity) { "0x{0:X}" -f $DppAffinity } else { "?" }
            $DppBgStr = if ($null -ne $DppBgPriority) { $DppBgPriority } else { "?" }
            $DppGPUStr = if ($null -ne $DppGPU) { $DppGPU } else { "?" }
            $DppCPUStr = if ($null -ne $DppCPU) { $DppCPU } else { "?" }
            Write-Host "  [3] DISPLAYPOSTPROCESSING:" -ForegroundColor Cyan
            Write-Host "      Afinita: $DppAffinityHex  |  BgPri: $DppBgStr  |  GPU: $DppGPUStr  |  CPU: $DppCPUStr" -ForegroundColor Gray
        }
        catch {
            Write-Host "  [3] DISPLAYPOSTPROCESSING: Nelze načíst" -ForegroundColor Yellow
        }
        Write-Host ""
        Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host ""
        # Menu Options
        Write-Host "Vyberte profil k úpravě:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[1] Upravit GAMES Profil (interaktivně)" -ForegroundColor Cyan
        Write-Host "    → Nastavení pro hry a interaktivní aplikace" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[2] Upravit AUDIO Profil (interaktivně)" -ForegroundColor Cyan
        Write-Host "    → Nastavení pro audio aplikace a DAW software" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[3] Upravit DISPLAYPOSTPROCESSING Profil (interaktivně)" -ForegroundColor Cyan
        Write-Host "    → Nastavení pro DWM a grafické post-processing" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[4] Obnovit Původní Hodnoty (OEM výchozí)" -ForegroundColor Yellow
        Write-Host "    → Obnoví všechny 3 profily na OEM výchozí hodnoty" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[Q] Zpět do Hlavního Menu" -ForegroundColor Red
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
        $choice = Read-Host -Prompt "Zadejte svou volbu"
        switch ($choice) {
            '1' { Edit-GameProfile }
            '2' { Edit-AudioProfile }
            '3' { Edit-DisplayPostProcessingProfile }
            '4' { Restore-MMCSSDefaults }
            'Q' { return }
            'q' { return }
            default {
                Write-Warning "Neplatná volba. Zadejte 1, 2, 3, 4 nebo Q."
                Start-Sleep -Seconds 2
            }
        }
    }
}
# ═══════════════════════════════════════════════════════════════════════════
# PROFILE RESTORE FUNCTION
# ═══════════════════════════════════════════════════════════════════════════
function Restore-MMCSSDefaults {
    <#
    .SYNOPSIS
        Restore all MMCSS profiles to OEM defaults.
    .DESCRIPTION
        Obnoví všechny 3 MMCSS profily (Games, Audio, DisplayPostProcessing)
        na výchozí hodnoty dodávané výrobcem (OEM).
        OEM VÝCHOZÍ HODNOTY:
        GAMES:
          • Affinity = 0 (Bez afinity)
          • GPU Priority = 8 (Maximum)
          • Priority = 6 (Vysoká)
          • Clock Rate = 10000
          • Background Only = "False"
          • Scheduling Category = "High"
          • SFIO Priority = "High"
        AUDIO:
          • Affinity = 0
          • GPU Priority = 8
          • Priority = 6
          • Clock Rate = 10000
          • Background Only = "True"
          • Scheduling Category = "Medium"
        DISPLAYPOSTPROCESSING:
          • Affinity = 0
          • BackgroundPriority = 8
          • GPU Priority = 8
          • Priority = 8
          • Clock Rate = 10000
          • Background Only = "True"
          • Scheduling Category = "High"
    .NOTES
        Uses Invoke-RegistryOperation from Core.psm1 for safe registry modification.
    #>
    [CmdletBinding()]
    param()
    Clear-Host
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host "  OBNOVENÍ MMCSS PROFILŮ NA OEM VÝCHOZÍ HODNOTY" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host ""
    $confirm = Read-Host "Opravdu chcete obnovit všechny profily? (Ano/Ne)"
    if ($confirm -notmatch '^a') {
        Write-Host "Operace zrušena." -ForegroundColor Gray
        Start-Sleep -Seconds 1
        return
    }
    Write-Host ""
    Write-Host "Obnovuji GAMES profil..." -ForegroundColor Cyan
    try {
        # GAMES Profile OEM Defaults
        Invoke-RegistryOperation -Path $script:GamesPath -Name "Affinity" -Value 0 -Type DWord | Out-Null
        Invoke-RegistryOperation -Path $script:GamesPath -Name "GPU Priority" -Value 8 -Type DWord | Out-Null
        Invoke-RegistryOperation -Path $script:GamesPath -Name "Priority" -Value 6 -Type DWord | Out-Null
        Invoke-RegistryOperation -Path $script:GamesPath -Name "Clock Rate" -Value 10000 -Type DWord | Out-Null
        Invoke-RegistryOperation -Path $script:GamesPath -Name "Background Only" -Value "False" -Type String | Out-Null
        Invoke-RegistryOperation -Path $script:GamesPath -Name "Scheduling Category" -Value "High" -Type String | Out-Null
        Invoke-RegistryOperation -Path $script:GamesPath -Name "SFIO Priority" -Value "High" -Type String | Out-Null
        Write-Host "✓ GAMES profil obnoven" -ForegroundColor Green
    }
    catch {
        Write-Warning "✗ GAMES profil: $($_.Exception.Message)"
    }
    Write-Host "Obnovuji AUDIO profil..." -ForegroundColor Cyan
    try {
        # AUDIO Profile OEM Defaults
        Invoke-RegistryOperation -Path $script:AudioPath -Name "Affinity" -Value 0 -Type DWord | Out-Null
        Invoke-RegistryOperation -Path $script:AudioPath -Name "GPU Priority" -Value 8 -Type DWord | Out-Null
        Invoke-RegistryOperation -Path $script:AudioPath -Name "Priority" -Value 6 -Type DWord | Out-Null
        Invoke-RegistryOperation -Path $script:AudioPath -Name "Clock Rate" -Value 10000 -Type DWord | Out-Null
        Invoke-RegistryOperation -Path $script:AudioPath -Name "Background Only" -Value "True" -Type String | Out-Null
        Invoke-RegistryOperation -Path $script:AudioPath -Name "Scheduling Category" -Value "Medium" -Type String | Out-Null
        Write-Host "✓ AUDIO profil obnoven" -ForegroundColor Green
    }
    catch {
        Write-Warning "✗ AUDIO profil: $($_.Exception.Message)"
    }
    Write-Host "Obnovuji DISPLAYPOSTPROCESSING profil..." -ForegroundColor Cyan
    try {
        # DISPLAYPOSTPROCESSING Profile OEM Defaults
        Invoke-RegistryOperation -Path $script:DisplayPath -Name "Affinity" -Value 0 -Type DWord | Out-Null
        Invoke-RegistryOperation -Path $script:DisplayPath -Name "BackgroundPriority" -Value 8 -Type DWord | Out-Null
        Invoke-RegistryOperation -Path $script:DisplayPath -Name "GPU Priority" -Value 8 -Type DWord | Out-Null
        Invoke-RegistryOperation -Path $script:DisplayPath -Name "Priority" -Value 8 -Type DWord | Out-Null
        Invoke-RegistryOperation -Path $script:DisplayPath -Name "Clock Rate" -Value 10000 -Type DWord | Out-Null
        Invoke-RegistryOperation -Path $script:DisplayPath -Name "Background Only" -Value "True" -Type String | Out-Null
        Invoke-RegistryOperation -Path $script:DisplayPath -Name "Scheduling Category" -Value "High" -Type String | Out-Null
        Write-Host "✓ DISPLAYPOSTPROCESSING profil obnoven" -ForegroundColor Green
    }
    catch {
        Write-Warning "✗ DISPLAYPOSTPROCESSING profil: $($_.Exception.Message)"
    }
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  OBNOVA DOKONČENA!" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "Doporučujeme restart aplikací/her pro uplatnění změn." -ForegroundColor Yellow
    Write-Host ""
    $null = Read-Host "Stiskněte Enter"
}
# ═══════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS - AFFINITY & CPU INFO
# ═══════════════════════════════════════════════════════════════════════════
function Get-AffinityMask {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$CoreRange
    )
    # Inicializace proměnných s explicitními typy
    [UInt64]$AffinityMask = 0
    [int]$StartCore = 0
    [int]$EndCore = 0
    [int]$TotalCores = 0
    # Detekce počtu jader v systému
    try {
        $TotalCores = [int]$env:NUMBER_OF_PROCESSORS
        if ($TotalCores -le 0) {
            Write-Error "Nepodařilo se detekovat počet CPU jader. NUMBER_OF_PROCESSORS=$($env:NUMBER_OF_PROCESSORS)"
            return $null
        }
    }
    catch {
        Write-Error "Chyba při detekci počtu CPU jader: $($_.Exception.Message)"
        return $null
    }
    # Parsing vstupu pomocí regex + switch
    try {
        switch -Regex ($CoreRange.Trim().ToLower()) {
            # Formát: "posledni X" (např. "posledni 2" na 8-core = jádra 6-7)
            "^posledni\s+(\d+)$" {
                [int]$Count = [int]$matches[1]
                if ($Count -le 0) {
                    Write-Warning "Počet jader musí být kladné číslo (zadáno: $Count)"
                    return $null
                }
                if ($Count -gt $TotalCores) {
                    Write-Warning "Požadováno $Count jader, ale systém má pouze $TotalCores. Použiju všechna dostupná."
                    $Count = $TotalCores
                }
                $StartCore = $TotalCores - $Count
                $EndCore = $TotalCores - 1
                break
            }
            # Formát: "prvni X" (např. "prvni 4" = jádra 0-3)
            "^prvni\s+(\d+)$" {
                [int]$Count = [int]$matches[1]
                if ($Count -le 0) {
                    Write-Warning "Počet jader musí být kladné číslo (zadáno: $Count)"
                    return $null
                }
                if ($Count -gt $TotalCores) {
                    Write-Warning "Požadováno $Count jader, ale systém má pouze $TotalCores. Použiju všechna dostupná."
                    $Count = $TotalCores
                }
                $StartCore = 0
                $EndCore = $Count - 1
                break
            }
            # Formát: "X-Y" (např. "0-7" = rozsah jader)
            "^\d+-\d+$" {
                $Parts = $CoreRange.Split('-')
                if (-not [int]::TryParse($Parts[0], [ref]$StartCore)) {
                    Write-Warning "Neplatný formát: '$CoreRange'. Očekávám formát 'X-Y' (např. '0-7')."
                    return $null
                }
                if (-not [int]::TryParse($Parts[1], [ref]$EndCore)) {
                    Write-Warning "Neplatný formát: '$CoreRange'. Očekávám formát 'X-Y' (např. '0-7')."
                    return $null
                }
                break
            }
            # Formát: "X,Y,Z" (seznam jader, např. "2,4,6,8")
            "^\d+(,\d+)+$" {
                # Parse seznam čísel oddělených čárkami
                $CoreList = $CoreRange -split ',' | ForEach-Object { 
                    $coreNum = 0
                    if ([int]::TryParse($_.Trim(), [ref]$coreNum)) {
                        $coreNum
                    }
                }
                # Validace a výpočet masky pro každé jádro v seznamu
                [UInt64]$ListMask = 0
                foreach ($core in $CoreList) {
                    if ($core -lt 0) {
                        Write-Warning "Číslo jádra $core je záporné, přeskakuji."
                        continue
                    }
                    if ($core -ge $TotalCores) {
                        Write-Warning "Číslo jádra $core překračuje počet dostupných jader ($TotalCores), přeskakuji."
                        continue
                    }
                    if ($core -gt 63) {
                        Write-Warning "Číslo jádra $core překračuje maximum (63), přeskakuji."
                        continue
                    }
                    # Nastavit bit pro toto jádro
                    $ListMask = $ListMask -bor ([UInt64]1 -shl $core)
                }
                # Pokud je maska 0, nic nebylo vybráno
                if ($ListMask -eq 0) {
                    Write-Warning "Žádné platné jádro nebylo vybráno ze seznamu '$CoreRange'"
                    return $null
                }
                # Konverze a návrat (speciální handling pro seznam)
                [string]$ListHexValue = $ListMask.ToString('X8')
                return [PSCustomObject]@{
                    HodnotaDecimal = [UInt64]$ListMask
                    RegEditFormat  = "dword:$ListHexValue"
                }
            }
            # Formát: "X" (jedno jádro)
            "^\d+$" {
                if (-not [int]::TryParse($CoreRange, [ref]$StartCore)) {
                    Write-Warning "Neplatné číslo jádra: '$CoreRange'"
                    return $null
                }
                $EndCore = $StartCore
                break
            }
            # Formát: "vsechny" (hodnota 0 = bez afinity)
            "^vsechny$" {
                # Speciální případ: vracíme 0 (bez afinity)
                return [PSCustomObject]@{
                    HodnotaDecimal = [UInt64]0
                    RegEditFormat  = "dword:00000000"
                }
            }
            # Nerozpoznaný formát
            default {
                Write-Warning "Nerozpoznaný formát vstupu: '$CoreRange'"
                Write-Host "Podporované formáty:" -ForegroundColor Yellow
                Write-Host "  • 'posledni X' (např. 'posledni 2')" -ForegroundColor Gray
                Write-Host "  • 'prvni X' (např. 'prvni 4')" -ForegroundColor Gray
                Write-Host "  • 'X-Y' (např. '0-7')" -ForegroundColor Gray
                Write-Host "  • 'X,Y,Z' (seznam, např. '2,4,6,8')" -ForegroundColor Gray
                Write-Host "  • 'X' (jedno jádro, např. '5')" -ForegroundColor Gray
                Write-Host "  • 'vsechny' (bez afinity)" -ForegroundColor Gray
                return $null
            }
        }
    }
    catch {
        Write-Error "Chyba při parsování vstupu '$CoreRange': $($_.Exception.Message)"
        return $null
    }
    # Edge case: StartCore větší než EndCore → prohodíme
    if ($StartCore -gt $EndCore) {
        Write-Verbose "StartCore ($StartCore) > EndCore ($EndCore), prohazuji..."
        [int]$Temp = $StartCore
        $StartCore = $EndCore
        $EndCore = $Temp
    }
    # Validace rozsahu (maximum 63, protože UInt64 = 64 bitů)
    if ($StartCore -lt 0) {
        Write-Warning "StartCore ($StartCore) je záporné. Nastavuji na 0."
        $StartCore = 0
    }
    if ($EndCore -gt 63) {
        Write-Warning "EndCore ($EndCore) překračuje maximum (63). Nastavuji na 63."
        $EndCore = 63
    }
    if ($StartCore -ge $TotalCores) {
        Write-Warning "StartCore ($StartCore) je mimo rozsah dostupných jader (0-$($TotalCores - 1))"
        return $null
    }
    if ($EndCore -ge $TotalCores) {
        Write-Warning "EndCore ($EndCore) překračuje počet jader ($TotalCores). Upravuji na $($TotalCores - 1)."
        $EndCore = $TotalCores - 1
    }
    # Výpočet bitové masky
    # Princip: Pro každé jádro i nastavíme bit na pozici i
    # Příklad: Jádra 0-3 → 0b1111 = 15
    try {
        for ([int]$i = $StartCore; $i -le $EndCore; $i++) {
            # Bitwise OR: AffinityMask |= (1 << i)
            # Pro jádro 0: mask |= (1 << 0) = mask | 1     = 0b00000001
            # Pro jádro 1: mask |= (1 << 1) = mask | 2     = 0b00000011
            # Pro jádro 2: mask |= (1 << 2) = mask | 4     = 0b00000111
            # atd.
            $AffinityMask = $AffinityMask -bor ([UInt64]1 -shl $i)
        }
    }
    catch {
        Write-Error "Chyba při výpočtu bitové masky: $($_.Exception.Message)"
        return $null
    }
    # Konverze na hexadecimální string (formát pro registry)
    [string]$HexValue = $AffinityMask.ToString('X8')
    # Výstup jako PSCustomObject
    return [PSCustomObject]@{
        HodnotaDecimal = [UInt64]$AffinityMask
        RegEditFormat  = "dword:$HexValue"
    }
}
function Get-CPUInfo {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    try {
        $cpu = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop
        $manufacturer = [string]$cpu.Manufacturer
        $name = [string]$cpu.Name
        $cores = [int]$cpu.NumberOfCores
        $threads = [int]$cpu.NumberOfLogicalProcessors
        # ── DETEKCE P-CORES / E-CORES (Intel 12th gen+) ──────────────
        # Princip: P-cores mají Hyper-Threading (2 thready/core)
        #          E-cores nemají HT (1 thread/core)
        # Vzorec:  P-cores = Threads - Cores
        #          E-cores = Cores - P-cores
        [int]$pCores = 0
        [int]$eCores = 0
        [string]$architecture = "Traditional"  # Traditional / Hybrid
        if ($manufacturer -match "Intel" -and $threads -gt $cores) {
            # Možná hybrid architektura (Alder Lake+)
            $pCores = $threads - $cores
            $eCores = $cores - $pCores
            # Validace: E-cores musí být > 0 (ne >=, aby se vyloučily CPU s 0 E-cores jako i3-12100)
            # FIX C-3: Změněno -ge na -gt pro správnou detekci Hybrid vs Traditional-HT
            if ($eCores -gt 0 -and $pCores -gt 0) {
                $architecture = "Hybrid"
            }
            else {
                # Fallback: tradiční HT architektura
                $architecture = "Traditional-HT"
                $pCores = $cores
                $eCores = 0
            }
        }
        elseif ($threads -eq $cores) {
            # Bez Hyper-Threading
            $architecture = "Traditional"
            $pCores = $cores
            $eCores = 0
        }
        else {
            # Hyper-Threading (AMD nebo starší Intel)
            $architecture = "Traditional-HT"
            $pCores = $cores
            $eCores = 0
        }
        # ── AMD CCD DETEKCE (Ryzen 5000+) ──────────────────────────
        # Placeholder pro budoucí implementaci
        # TODO: Detekce AMD CCD přes NUMA topologii nebo MSR registry
        [int]$ccdCount = 0
        if ($manufacturer -match "AMD" -and $name -match "Ryzen") {
            # Odhad CCD (např. Ryzen 9 5950X = 2 CCDs)
            if ($cores -ge 12) {
                $ccdCount = [math]::Ceiling($cores / 8)
            }
            elseif ($cores -ge 6) {
                $ccdCount = 1
            }
        }
        # FIX M-1: Warning pro CPU s >64 threads (Server EPYC, Threadripper)
        # Důvod: Windows podporuje pouze 64 cores v jedné Processor Group
        if ($threads -gt 64) {
            Write-Warning ""
            Write-Warning "═══════════════════════════════════════════════════════════"
            Write-Warning "⚠️  UPOZORNĚNÍ: CPU má $threads logických jader (threads)"
            Write-Warning "═══════════════════════════════════════════════════════════"
            Write-Warning ""
            Write-Warning "Windows podporuje pouze 64 jader v jedné Processor Group."
            Write-Warning "Affinity nastavení bude OMEZENO na cores 0-63."
            Write-Warning ""
            Write-Warning "Pro přístup k jádrům 64-$(($threads - 1)) je nutné použít"
            Write-Warning "Processor Groups API (pokročilé, vyžaduje native kód)."
            Write-Warning ""
            Write-Warning "Tento skript pracuje pouze s Processor Group 0 (cores 0-63)."
            Write-Warning ""
            Write-Warning "═══════════════════════════════════════════════════════════"
            Write-Warning ""
        }
        return [PSCustomObject]@{
            Manufacturer = $manufacturer
            Name         = $name
            Cores        = $cores
            Threads      = $threads
            Architecture = $architecture
            PCores       = $pCores
            ECores       = $eCores
            CCDCount     = $ccdCount
        }
    }
    catch {
        Write-Warning "Chyba při získávání informací o CPU: $($_.Exception.Message)"
        Write-Warning "Používám fallback detekci na základě env proměnné NUMBER_OF_PROCESSORS."
        # FIX C-1: Bezpečný fallback pro W10/W11/Server
        # Důvod: Původní vzorec (Threads / 2) vrací 0 pro single-core CPU!
        [int]$detectedThreads = [int]$env:NUMBER_OF_PROCESSORS
        [int]$detectedCores = 0
        [string]$fallbackArch = "Unknown"
        # Heuristika pro moderní CPU (W10/W11/Server 2023+)
        if ($detectedThreads -ge 4 -and ($detectedThreads % 2) -eq 0) {
            # Většina moderních CPU má HT/SMT (sudé číslo >= 4)
            $detectedCores = $detectedThreads / 2
            $fallbackArch = "Traditional-HT"
        }
        elseif ($detectedThreads -eq 2) {
            # Dual-core: Neznáme, zda má HT nebo ne
            # Konzervativní přístup: předpokládáme BEZ HT (2 fyzické cores)
            $detectedCores = 2
            $fallbackArch = "Traditional"
        }
        else {
            # Single-core nebo liché číslo threads (vzácné)
            # NIKDY nevracíme 0! Minimálně 1 core.
            $detectedCores = [math]::Max(1, $detectedThreads)
            $fallbackArch = "Traditional"
        }
        return [PSCustomObject]@{
            Manufacturer = "Unknown"
            Name         = "Unknown"
            Cores        = $detectedCores  # ✅ NIKDY 0!
            Threads      = $detectedThreads
            Architecture = $fallbackArch
            PCores       = 0
            ECores       = 0
            CCDCount     = 0
        }
    }
}
function Get-SmartAffinitySuggestion {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Games', 'Audio', 'DisplayPostProcessing')]
        [string]$ProfileType,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Conservative', 'Advanced')]
        [string]$Strategy = 'Conservative'
    )
    # Získání CPU informací
    $cpuInfo = Get-CPUInfo
    # ── BEZPEČNOSTNÍ VALIDACE ────────────────────────────────────
    # Ochrana proti neznámým/nepodporovaným architekturám
    if ($cpuInfo.Architecture -eq "Unknown" -or $cpuInfo.Threads -le 0) {
        Write-Warning "⚠️  VAROVÁNÍ: Nepodařilo se detekovat CPU architekturu!"
        Write-Warning "   Doporučuji použít 'vsechny' (bez afinity) pro maximální stabilitu."
        return [PSCustomObject]@{
            RecommendedInput = "vsechny"
            AlternativeInput = $null
            Description      = "⚠️  SAFE MODE: Bez afinity (neznámá architektura)"
            AlternativeDesc  = $null
            Reason           = "CPU architektura nebyla rozpoznána. Systém sám řídí zatížení."
            SafetyLevel      = "CRITICAL"
        }
    }
    # Inicializace výsledku
    $suggestion = [PSCustomObject]@{
        RecommendedInput = "vsechny"
        AlternativeInput = $null
        Description      = "✅ Doporučeno: Bez afinity (systém řídí sám)"
        AlternativeDesc  = $null
        Reason           = "Nejlepší volba pro většinu scénářů - systém dynamicky řídí zatížení."
        SafetyLevel      = "SAFE"
    }
    # ── INTEL HYBRID CPU (12th gen+) ──────────────────────────────
    if ($cpuInfo.Architecture -eq "Hybrid") {
        # FIX C-4: Clamp všechny hodnoty na Windows limit (0-63)
        # Důvod: Budoucí Xeon Hybrid nebo EPYC může mít >64 threads
        $pCoreEnd = [math]::Min(63, ($cpuInfo.PCores * 2) - 1)
        $eCoreStart = [math]::Min(64, $cpuInfo.PCores * 2)
        $eCoreEnd = [math]::Min(63, $cpuInfo.Threads - 1)
        # Warning pokud E-cores jsou mimo rozsah Windows afinity
        if ($eCoreStart -gt 63) {
            Write-Warning "⚠️  E-cores začínají na pozici $eCoreStart, což je mimo Windows limit (0-63)."
            Write-Warning "   E-cores NEBUDOU dostupné pro affinity. Použijte pouze P-cores (0-$pCoreEnd)."
        }
        if ($ProfileType -eq 'Games') {
            # ═══════════════════════════════════════════════════════
            # GAMES PROFIL - Vždy P-cores
            # ═══════════════════════════════════════════════════════
            $suggestion.RecommendedInput = "0-$pCoreEnd"
            $suggestion.Description = "🎮 PRO HRY: Použij P-cores (Performance jádra)"
            $suggestion.Reason = "P-cores poskytují nejvyšší výkon pro náročné hry. E-cores jsou ideální pro background úlohy."
            $suggestion.SafetyLevel = "SAFE"
            $suggestion.AlternativeInput = $null
            $suggestion.AlternativeDesc = $null
        }
        elseif ($ProfileType -eq 'Audio') {
            # ═══════════════════════════════════════════════════════
            # AUDIO PROFIL - Konzervativní vs Pokročilá strategie
            # ═══════════════════════════════════════════════════════
            if ($Strategy -eq 'Conservative') {
                # KONZERVATIVNÍ: Audio na P-cores (sdílené s hry)
                $suggestion.RecommendedInput = "0-$pCoreEnd"
                $suggestion.Description = "🎵 KONZERVATIVNÍ: Audio na P-cores"
                $suggestion.Reason = "P-cores zajistí nejnižší latenci (vyšší frekvence). Sdíleno s hrami, ale stabilní."
                $suggestion.SafetyLevel = "SAFE"
                # Alternativa: E-cores pro pokročilé
                $suggestion.AlternativeInput = "$eCoreStart-$eCoreEnd"
                $suggestion.AlternativeDesc = "🔬 POKROČILÉ: Audio na E-cores (dedikované)"
            }
            else {
                # POKROČILÁ: Audio na E-cores (separace od her)
                $suggestion.RecommendedInput = "$eCoreStart-$eCoreEnd"
                $suggestion.Description = "🔬 POKROČILÉ: Audio na E-cores (dedikované zdroje)"
                $suggestion.Reason = "E-cores jsou dedikované pro audio - žádné konflikty s hrami. Může snížit latenci při vysoké zátěži her."
                $suggestion.SafetyLevel = "EXPERIMENTAL"
                # Alternativa: P-cores pro konzervativní
                $suggestion.AlternativeInput = "0-$pCoreEnd"
                $suggestion.AlternativeDesc = "🎵 KONZERVATIVNÍ: Audio na P-cores (sdílené s hrami)"
            }
        }
        else {
            # DisplayPostProcessing: Všechna jádra OK
            $suggestion.Description = "🖥️ PRO DISPLAY: Bez afinity (systém řídí)"
            $suggestion.SafetyLevel = "SAFE"
        }
    }
    # ── AMD RYZEN (CCD) ───────────────────────────────────────────
    elseif ($cpuInfo.Manufacturer -match "AMD" -and $cpuInfo.CCDCount -gt 0) {
        if ($ProfileType -eq 'Games') {
            # Pro hry: Preferuj první CCD (obvykle rychlejší)
            $ccdCores = [math]::Min(8, $cpuInfo.Cores)
            $suggestion.RecommendedInput = "0-$($ccdCores - 1)"
            $suggestion.Description = "🎮 PRO HRY: Použij CCD0 (první chiplet)"
            $suggestion.Reason = "První CCD obvykle má nejnižší latenci. Pro multi-CCD CPU."
            $suggestion.SafetyLevel = "SAFE"
        }
        elseif ($ProfileType -eq 'Audio') {
            # Audio: Také první CCD
            $ccdCores = [math]::Min(8, $cpuInfo.Cores)
            $suggestion.RecommendedInput = "0-$($ccdCores - 1)"
            $suggestion.Description = "🎵 PRO AUDIO: Použij CCD0 (první chiplet)"
            $suggestion.Reason = "První CCD zajistí nejnižší latenci pro audio zpracování."
            $suggestion.SafetyLevel = "SAFE"
        }
    }
    # ── TRADIČNÍ CPU (bez hybrid) ─────────────────────────────────
    else {
        # Pro všechny profily: Bez afinity
        $suggestion.Description = "✅ UNIVERZÁLNÍ: Bez afinity (systém řídí)"
        $suggestion.Reason = "Tradiční CPU - systém efektivně řídí zatížení napříč jádry."
        $suggestion.SafetyLevel = "SAFE"
    }
    
    return $suggestion
}
function Select-AffinityStrategy {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $cpuInfo = Get-CPUInfo
    # Pouze pro Intel Hybrid CPU
    if ($cpuInfo.Architecture -ne "Hybrid") {
        return 'Conservative'  # Default pro non-hybrid
    }
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "  INTEL HYBRID CPU DETEKOVÁNO!" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "Máte $($cpuInfo.PCores) P-cores a $($cpuInfo.ECores) E-cores." -ForegroundColor White
    Write-Host ""
    Write-Host "Vyberte strategii pro AUDIO afinitu:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  [1] KONZERVATIVNÍ (DOPORUČENO)" -ForegroundColor Green
    Write-Host "      → Audio na P-cores (sdílené s hrami)" -ForegroundColor Gray
    Write-Host "      → Nejnižší latence (vyšší frekvence)" -ForegroundColor Gray
    Write-Host "      → Stabilní, prověřené" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  [2] POKROČILÁ (EXPERIMENTÁLNÍ)" -ForegroundColor Yellow
    Write-Host "      → Audio na E-cores (dedikované)" -ForegroundColor Gray
    Write-Host "      → Separace od her - žádné konflikty" -ForegroundColor Gray
    Write-Host "      → Může pomoci při vysoké zátěži" -ForegroundColor Gray
    Write-Host ""
    Write-Host "⚠️  VAROVÁNÍ: Pokročilá = experimentální!" -ForegroundColor Red
    Write-Host "   Testuj stabilitu audio při hraní." -ForegroundColor Red
    Write-Host ""
    $choice = Read-Host "Vyberte strategii (1 nebo 2, Enter = 1)"
    if ($choice -eq '2') {
        Write-Host ""
        Write-Host "✅ Vybrána POKROČILÁ strategie" -ForegroundColor Yellow
        return 'Advanced'
    }
    else {
        Write-Host ""
        Write-Host "✅ Vybrána KONZERVATIVNÍ strategie" -ForegroundColor Green
        return 'Conservative'
    }
}
function Convert-AffinityMaskToCoreList {
    [CmdletBinding()]
    [OutputType([int[]])]
    param (
        [Parameter(Mandatory = $true)]
        [UInt64]$AffinityMask
    )
    # Pokud je maska 0, vrať prázdný pole (bez afinity)
    if ($AffinityMask -eq 0) {
        return @()
    }
    # Seznam vybraných jader
    [System.Collections.ArrayList]$SelectedCores = @()
    # Projdi všech 64 možných bitů (jader)
    for ([int]$i = 0; $i -lt 64; $i++) {
        # Testuj, zda je bit na pozici i nastaven
        # Bitwise AND: Pokud (Mask & (1 << i)) != 0, pak jádro i je vybráno
        if (($AffinityMask -band ([UInt64]1 -shl $i)) -ne 0) {
            $null = $SelectedCores.Add($i)
        }
    }
    return [int[]]$SelectedCores.ToArray()
}
function Show-CPUTopology {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [int]$Threads = 0,
        [Parameter(Mandatory = $false)]
        [array]$HighlightCores = @()
    )
    # Získání CPU informací
    $cpuInfo = Get-CPUInfo
    if ($Threads -le 0) {
        $Threads = $cpuInfo.Threads
    }
    Write-Host ""
    Write-Host "════════════════════ CPU TOPOLOGY ════════════════════" -ForegroundColor Cyan
    Write-Host ""
    # ── ZOBRAZENÍ INFORMACÍ O CPU ────────────────────────────────────
    Write-Host "  CPU: " -NoNewline -ForegroundColor Gray
    Write-Host "$($cpuInfo.Name)" -ForegroundColor White
    if ($cpuInfo.Architecture -eq "Hybrid") {
        Write-Host "  Architektura: " -NoNewline -ForegroundColor Gray
        Write-Host "HYBRID " -NoNewline -ForegroundColor Yellow
        Write-Host "(Intel 12th gen+)" -ForegroundColor Gray
        Write-Host "  P-cores (Performance): " -NoNewline -ForegroundColor Gray
        Write-Host "$($cpuInfo.PCores) jader " -NoNewline -ForegroundColor Green
        Write-Host "→ " -NoNewline -ForegroundColor Gray
        Write-Host "Core 0-$(($cpuInfo.PCores * 2) - 1)" -ForegroundColor Green
        Write-Host "  E-cores (Efficiency):  " -NoNewline -ForegroundColor Gray
        Write-Host "$($cpuInfo.ECores) jader " -NoNewline -ForegroundColor Cyan
        Write-Host "→ " -NoNewline -ForegroundColor Gray
        Write-Host "Core $(($cpuInfo.PCores * 2))-$(($cpuInfo.Threads) - 1)" -ForegroundColor Cyan
    }
    elseif ($cpuInfo.CCDCount -gt 0) {
        Write-Host "  Architektura: " -NoNewline -ForegroundColor Gray
        Write-Host "AMD Ryzen (CCD: $($cpuInfo.CCDCount))" -ForegroundColor Magenta
    }
    else {
        Write-Host "  Architektura: " -NoNewline -ForegroundColor Gray
        Write-Host "$($cpuInfo.Architecture)" -ForegroundColor White
    }
    Write-Host ""
    # ── LEGENDA ──────────────────────────────────────────────────────
    if ($cpuInfo.Architecture -eq "Hybrid") {
        Write-Host "  LEGENDA: " -NoNewline -ForegroundColor Gray
        Write-Host "[P] " -NoNewline -ForegroundColor Green
        Write-Host "P-core  " -NoNewline -ForegroundColor Gray
        Write-Host "[E] " -NoNewline -ForegroundColor Cyan
        Write-Host "E-core  " -NoNewline -ForegroundColor Gray
        if ($HighlightCores.Count -gt 0) {
            Write-Host "[*] " -NoNewline -ForegroundColor Yellow
            Write-Host "Vybrané" -ForegroundColor Gray
        }
        Write-Host ""
        Write-Host ""
    }
    elseif ($HighlightCores.Count -gt 0) {
        Write-Host "  LEGENDA: " -NoNewline -ForegroundColor Gray
        Write-Host "[ ] " -NoNewline -ForegroundColor White
        Write-Host "Dostupné  " -NoNewline -ForegroundColor Gray
        Write-Host "[*] " -NoNewline -ForegroundColor Yellow
        Write-Host "Vybrané" -ForegroundColor Gray
        Write-Host ""
        Write-Host ""
    }
    # ── MATICE CPU JADER (8 per line) ────────────────────────────────
    Write-Host "  " -NoNewline
    for ($i = 0; $i -lt $Threads; $i++) {
        # Určení barvy podle architektury
        $color = "White"
        $prefix = " "
        if ($cpuInfo.Architecture -eq "Hybrid") {
            # Intel Hybrid: P-cores (0 až P*2-1), E-cores (P*2 až Threads-1)
            if ($i -lt ($cpuInfo.PCores * 2)) {
                $color = "Green"
                $prefix = "P"
            }
            else {
                $color = "Cyan"
                $prefix = "E"
            }
        }
        # Zvýraznění vybraných jader
        if ($HighlightCores -contains $i) {
            $color = "Yellow"
            $prefix = "*"
        }
        # Výpis jádra
        Write-Host ("[$prefix{0,2}]" -f $i) -NoNewline -ForegroundColor $color
        # Nový řádek po 8 jádrech
        if ((($i + 1) % 8) -eq 0 -and ($i + 1) -lt $Threads) {
            Write-Host ""
            Write-Host "  " -NoNewline
        }
        else {
            Write-Host " " -NoNewline
        }
    }
    Write-Host ""
    Write-Host ""
    # ── LINEÁRNÍ SEZNAM ──────────────────────────────────────────────
    Write-Host "  ───────────────────────────────────────────────────────" -ForegroundColor Gray
    Write-Host "  Lineární: " -NoNewline -ForegroundColor Cyan
    for ($j = 0; $j -lt $Threads; $j++) {
        $color = "White"
        if ($cpuInfo.Architecture -eq "Hybrid") {
            if ($j -lt ($cpuInfo.PCores * 2)) {
                $color = "Green"
            }
            else {
                $color = "Cyan"
            }
        }
        if ($HighlightCores -contains $j) {
            $color = "Yellow"
        }
        Write-Host "$j " -NoNewline -ForegroundColor $color
    }
    Write-Host ""
    Write-Host "  ───────────────────────────────────────────────────────" -ForegroundColor Gray
    Write-Host ""
}
# ═══════════════════════════════════════════════════════════════════════════
# MMCSS PROFILE EDIT FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════
function Edit-GameProfile {
    <#
    .SYNOPSIS
        Interactive editor for MMCSS Games profile.
    .DESCRIPTION
        Allows user to configure CPU affinity, GPU priority, and CPU priority
        for the MMCSS Games profile with smart suggestions and CPU topology visualization.
    #>
    [CmdletBinding()]
    param()
    # Registry path
    [string]$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
    # Ensure registry key exists
    if (-not (Test-Path -LiteralPath $RegPath)) {
        Write-Host ""
        Write-Host "Registry klíč pro Games profil neexistuje. Vytvářím..." -ForegroundColor Yellow
        try {
            New-Item -Path $RegPath -Force -ErrorAction Stop | Out-Null
            Write-Host "Registry klíč úspěšně vytvořen: $RegPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Nepodařilo se vytvořit registry klíč: $($_.Exception.Message)"
            Write-Host "Stiskněte klávesu pro návrat..." -ForegroundColor Red
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }
    }
    # Main menu loop
    while ($true) {
        Clear-Host
        # Load current values from registry
        [int]$CurrentAffinity = 0
        [int]$CurrentGPUPriority = 0
        [int]$CurrentCPUPriority = 0
        [string]$AffinityDisplay = "Nenastaveno"
        [array]$CurrentSelectedCores = @()
        try {
            $AffinityValue = Get-ItemProperty -LiteralPath $RegPath -Name "Affinity" -ErrorAction SilentlyContinue
            if ($null -ne $AffinityValue) {
                $CurrentAffinity = [int]$AffinityValue.Affinity
                if ($CurrentAffinity -eq 0) {
                    $AffinityDisplay = "0 (Bez afinity - systém řídí)"
                    $CurrentSelectedCores = @()
                }
                else {
                    $AffinityDisplay = "$CurrentAffinity (0x{0:X8})" -f $CurrentAffinity
                    $CurrentSelectedCores = Convert-AffinityMaskToCoreList -AffinityMask $CurrentAffinity
                }
            }
            $GPUPriorityValue = Get-ItemProperty -LiteralPath $RegPath -Name "GPU Priority" -ErrorAction SilentlyContinue
            if ($null -ne $GPUPriorityValue) {
                $CurrentGPUPriority = [int]$GPUPriorityValue.'GPU Priority'
            }
            $CPUPriorityValue = Get-ItemProperty -LiteralPath $RegPath -Name "Priority" -ErrorAction SilentlyContinue
            if ($null -ne $CPUPriorityValue) {
                $CurrentCPUPriority = [int]$CPUPriorityValue.Priority
            }
        }
        catch {
            Write-Warning "Chyba při načítání hodnot z registry: $($_.Exception.Message)"
        }
        # Display menu
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host "     ÚPRAVA GAMES PROFILU (MMCSS)                         " -ForegroundColor Green
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
        [int]$TotalCoresDisplay = 0
        try {
            $TotalCoresDisplay = [int]$env:NUMBER_OF_PROCESSORS
        }
        catch {
            $TotalCoresDisplay = 8
        }
        Write-Host "Informace o systému:" -ForegroundColor Cyan
        Write-Host "  CPU Jader celkem: $TotalCoresDisplay (indexováno 0-$($TotalCoresDisplay - 1))" -ForegroundColor White
        Show-CPUTopology -Threads $TotalCoresDisplay -HighlightCores $CurrentSelectedCores
        Write-Host "Podporované formáty pro CPU Afinitu:" -ForegroundColor Cyan
        Write-Host "  • 'posledni X'  → Posledních X jader (např. 'posledni 2')" -ForegroundColor Gray
        Write-Host "  • 'prvni X'     → Prvních X jader (např. 'prvni 4')" -ForegroundColor Gray
        Write-Host "  • 'X-Y'         → Rozsah jader (např. '0-7')" -ForegroundColor Gray
        Write-Host "  • 'X,Y,Z'       → Seznam jader (např. '2,4,6,8')" -ForegroundColor Gray
        Write-Host "  • 'X'           → Jedno jádro (např. '5')" -ForegroundColor Gray
        Write-Host "  • 'vsechny'     → Bez afinity (systém řídí sám) [DOPORUČENO]" -ForegroundColor Gray
        Write-Host ""
        Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Aktuální nastavení:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  [1] CPU Afinita       : $AffinityDisplay" -ForegroundColor Cyan
        Write-Host "      → Která CPU jádra může proces použít" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [2] GPU Priorita (1-8): $CurrentGPUPriority" -ForegroundColor Cyan
        Write-Host "      → Vyšší = více GPU času (8 = maximum)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [3] CPU Priorita (1-8): $CurrentCPUPriority" -ForegroundColor Cyan
        Write-Host "      → Vyšší = více CPU času (6 = doporučeno pro hry)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [4] Aplikovat Doporučený Herní Profil (Vše najednou)" -ForegroundColor Yellow
        Write-Host "      → Affinity=0, GPU Priority=8, CPU Priority=6" -ForegroundColor Gray
        Write-Host "      → Background Only=False, Scheduling=High, IO=High" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [B] Zpět do Předchozího Menu" -ForegroundColor Red
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
        $choice = Read-Host -Prompt "Zadejte svou volbu"
        switch ($choice) {
            '1' {
                Write-Host ""
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host "  NASTAVENÍ CPU AFINITY" -ForegroundColor Yellow
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host ""
                [int]$TotalCores = 0
                try {
                    $TotalCores = [int]$env:NUMBER_OF_PROCESSORS
                    Write-Host "Váš systém má $TotalCores logických procesorů (jádra 0 až $($TotalCores - 1))" -ForegroundColor White
                }
                catch {
                    Write-Warning "Nepodařilo se detekovat počet CPU jader."
                    $TotalCores = 8
                }
                Write-Host ""
                Write-Host "Podporované formáty:" -ForegroundColor Yellow
                Write-Host "  • 'posledni X'  - Posledních X jader (např. 'posledni 2')" -ForegroundColor Gray
                Write-Host "  • 'prvni X'     - Prvních X jader (např. 'prvni 4')" -ForegroundColor Gray
                Write-Host "  • 'X-Y'         - Rozsah jader (např. '0-7')" -ForegroundColor Gray
                Write-Host "  • 'X'           - Jedno jádro (např. '5')" -ForegroundColor Gray
                Write-Host "  • 'vsechny'     - Bez afinity (systém řídí sám) [DOPORUČENO]" -ForegroundColor Gray
                Write-Host ""
                $suggestion = Get-SmartAffinitySuggestion -ProfileType 'Games'
                Write-Host "💡 INTELIGENTNÍ DOPORUČENÍ:" -ForegroundColor Cyan
                Write-Host "   $($suggestion.Description)" -ForegroundColor Yellow
                Write-Host "   → Zadejte: '$($suggestion.RecommendedInput)'" -ForegroundColor Green
                Write-Host "   ℹ️  $($suggestion.Reason)" -ForegroundColor Gray
                Write-Host ""
                $InputAffinity = Read-Host "Zadejte afinitu"
                $AffinityResult = Get-AffinityMask -CoreRange $InputAffinity
                if ($null -ne $AffinityResult) {
                    # Use Invoke-RegistryOperation for auto-backup & privilege escalation
                    $regResult = Invoke-RegistryOperation `
                        -Path $RegPath `
                        -Name "Affinity" `
                        -Value $AffinityResult.HodnotaDecimal `
                        -Type DWord
                    if ($regResult.Success) {
                        Write-Host ""
                        Write-Host "CPU Afinita úspěšně nastavena na: $($AffinityResult.HodnotaDecimal) ($($AffinityResult.RegEditFormat))" -ForegroundColor Green
                        Write-Host "Pro obnovení na OEM výchozí hodnoty použijte volbu [3] Obnovit v hlavním menu." -ForegroundColor Gray
                        if ($AffinityResult.HodnotaDecimal -gt 0) {
                            Write-Host ""
                            Write-Host "Vybraná jádra (zvýrazněna žlutě):" -ForegroundColor Yellow
                            $SelectedCoresList = Convert-AffinityMaskToCoreList -AffinityMask $AffinityResult.HodnotaDecimal
                            Show-CPUTopology -Threads $TotalCores -HighlightCores $SelectedCoresList
                        }
                        else {
                            Write-Host ""
                            Write-Host "Afinita nastavena na 0 - systém bude řízení jader řídit sám." -ForegroundColor Cyan
                        }
                    }
                    else {
                        Write-Error "Chyba při aplikaci CPU afinity: $($regResult.Error)"
                    }
                }
                else {
                    Write-Warning "Neplatný vstup. Afinita nebyla změněna."
                }
                Write-Host ""
                Write-Host "Stiskněte klávesu pro pokračování..." -ForegroundColor White
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '2' {
                Write-Host ""
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host "  NASTAVENÍ GPU PRIORITY" -ForegroundColor Yellow
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "GPU Priorita určuje, kolik GPU času dostane proces." -ForegroundColor Gray
                Write-Host "Rozsah: 1-8 (8 = maximum, doporučeno pro hry)" -ForegroundColor Gray
                Write-Host ""
                $InputGPUPriority = Read-Host "Zadejte GPU Prioritu (1-8, doporučeno 8)"
                [int]$NewGPUPriority = 0
                if ([int]::TryParse($InputGPUPriority, [ref]$NewGPUPriority)) {
                    if ($NewGPUPriority -ge 1 -and $NewGPUPriority -le 8) {
                        # Use Invoke-RegistryOperation for auto-backup & privilege escalation
                        $regResult = Invoke-RegistryOperation `
                            -Path $RegPath `
                            -Name "GPU Priority" `
                            -Value $NewGPUPriority `
                            -Type DWord
                        if ($regResult.Success) {
                            Write-Host ""
                            Write-Host "GPU Priorita úspěšně nastavena na: $NewGPUPriority" -ForegroundColor Green
                            Write-Host "Pro obnovení na OEM výchozí hodnoty použijte volbu [3] Obnovit v hlavním menu." -ForegroundColor Gray
                        }
                        else {
                            Write-Error "Chyba při aplikaci GPU priority: $($regResult.Error)"
                        }
                    }
                    else {
                        Write-Warning "Neplatná hodnota. Musí být celé číslo od 1 do 8."
                    }
                }
                else {
                    Write-Warning "Neplatný vstup. GPU Priorita nebyla změněna."
                }
                Write-Host ""
                Write-Host "Stiskněte klávesu pro pokračování..." -ForegroundColor White
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '3' {
                Write-Host ""
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host "  NASTAVENÍ CPU PRIORITY" -ForegroundColor Yellow
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "CPU Priorita určuje, kolik CPU času dostane proces." -ForegroundColor Gray
                Write-Host "Rozsah: 1-8 (6 = doporučeno pro hry, 8 = maximum)" -ForegroundColor Gray
                Write-Host ""
                $InputCPUPriority = Read-Host "Zadejte CPU Prioritu (1-8, doporučeno 6)"
                [int]$NewCPUPriority = 0
                if ([int]::TryParse($InputCPUPriority, [ref]$NewCPUPriority)) {
                    if ($NewCPUPriority -ge 1 -and $NewCPUPriority -le 8) {
                        # Use Invoke-RegistryOperation for auto-backup & privilege escalation
                        $regResult = Invoke-RegistryOperation `
                            -Path $RegPath `
                            -Name "Priority" `
                            -Value $NewCPUPriority `
                            -Type DWord
                        if ($regResult.Success) {
                            Write-Host ""
                            Write-Host "CPU Priorita úspěšně nastavena na: $NewCPUPriority" -ForegroundColor Green
                            Write-Host "Pro obnovení na OEM výchozí hodnoty použijte volbu [3] Obnovit v hlavním menu." -ForegroundColor Gray
                        }
                        else {
                            Write-Error "Chyba při aplikaci CPU priority: $($regResult.Error)"
                        }
                    }
                    else {
                        Write-Warning "Neplatná hodnota. Musí být celé číslo od 1 do 8."
                    }
                }
                else {
                    Write-Warning "Neplatný vstup. CPU Priorita nebyla změněna."
                }
                Write-Host ""
                Write-Host "Stiskněte klávesu pro pokračování..." -ForegroundColor White
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '4' {
                Write-Host ""
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host "  APLIKACE DOPORUČENÉHO HERNÍHO PROFILU" -ForegroundColor Yellow
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Tento profil nastaví optimální hodnoty pro herní výkon:" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  • Affinity = 0 (Bez afinity - systém řídí)" -ForegroundColor White
                Write-Host "  • GPU Priority = 8 (Maximum)" -ForegroundColor White
                Write-Host "  • Priority = 6 (Doporučeno pro hry)" -ForegroundColor White
                Write-Host "  • Clock Rate = 10000 (0x2710)" -ForegroundColor White
                Write-Host "  • IOLatencyPolicy = 1 (Enabled)" -ForegroundColor White
                Write-Host "  • Background Only = False" -ForegroundColor White
                Write-Host "  • Scheduling Category = High" -ForegroundColor White
                Write-Host "  • SFIO Priority = High" -ForegroundColor White
                Write-Host "  • IO Priority = High" -ForegroundColor White
                Write-Host ""
                $Confirm = Read-Host "Aplikovat doporučený profil? (A/N)"
                if ($Confirm -eq 'A' -or $Confirm -eq 'a') {
                    # Use Invoke-RegistryOperation for auto-backup & privilege escalation
                    $allSuccess = $true
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "Affinity" -Value 0x00000000 -Type DWord
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "Affinity: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "GPU Priority" -Value 0x00000008 -Type DWord
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "GPU Priority: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "Priority" -Value 0x00000006 -Type DWord
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "Priority: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "Clock Rate" -Value 0x00002710 -Type DWord
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "Clock Rate: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "IOLatencyPolicy" -Value 0x00000001 -Type DWord
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "IOLatencyPolicy: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "Background Only" -Value "False" -Type String
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "Background Only: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "Scheduling Category" -Value "High" -Type String
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "Scheduling Category: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "SFIO Priority" -Value "High" -Type String
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "SFIO Priority: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "IO Priority" -Value "High" -Type String
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "IO Priority: $($result.Error)" }
                    if ($allSuccess) {
                        Write-Host ""
                        Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
                        Write-Host "║  DOPORUČENÝ HERNÍ PROFIL ÚSPĚŠNĚ APLIKOVÁN!               ║" -ForegroundColor Green
                        Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
                        Write-Host ""
                        Write-Host "Aplikovány OEM výchozí hodnoty pro herní profil." -ForegroundColor Gray
                        Write-Host ""
                        Write-Host "DOPORUČENÍ:" -ForegroundColor Yellow
                        Write-Host "  • Pro úplné použití změn restartujte hry/aplikace" -ForegroundColor Gray
                        Write-Host "  • Některé změny mohou vyžadovat restart systému" -ForegroundColor Gray
                        Write-Host "  • Pro obnovení použijte volbu [3] Obnovit v hlavním menu" -ForegroundColor Gray
                    }
                    else {
                        Write-Error "Chyba při aplikaci doporučeného profilu. Zkontrolujte výše uvedená varování."
                    }
                }
                else {
                    Write-Host "Operace zrušena." -ForegroundColor Yellow
                }
                Write-Host ""
                Write-Host "Stiskněte klávesu pro pokračování..." -ForegroundColor White
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            'B' { return }
            'b' { return }
            default {
                Write-Warning "Neplatná volba. Zadejte 1, 2, 3, 4 nebo B."
                Start-Sleep -Seconds 2
            }
        }
    }
}
function Edit-AudioProfile {
    <#
    .SYNOPSIS
        Interactive editor for MMCSS Audio profile.
    #>
    [CmdletBinding()]
    param()
    [string]$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Audio"
    if (-not (Test-Path -LiteralPath $RegPath)) {
        Write-Host ""
        Write-Host "Registry klíč pro Audio profil neexistuje. Vytvářím..." -ForegroundColor Yellow
        try {
            New-Item -Path $RegPath -Force -ErrorAction Stop | Out-Null
            Write-Host "Registry klíč úspěšně vytvořen: $RegPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Nepodařilo se vytvořit registry klíč: $($_.Exception.Message)"
            Write-Host "Stiskněte klávesu pro návrat..." -ForegroundColor Red
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }
    }
    while ($true) {
        Clear-Host
        [int]$CurrentAffinity = 0
        [int]$CurrentGPUPriority = 0
        [int]$CurrentCPUPriority = 0
        [string]$AffinityDisplay = "Nenastaveno"
        [array]$CurrentSelectedCores = @()
        try {
            $AffinityValue = Get-ItemProperty -LiteralPath $RegPath -Name "Affinity" -ErrorAction SilentlyContinue
            if ($null -ne $AffinityValue) {
                $CurrentAffinity = [int]$AffinityValue.Affinity
                if ($CurrentAffinity -eq 0) {
                    $AffinityDisplay = "0 (Bez afinity - systém řídí)"
                    $CurrentSelectedCores = @()
                }
                else {
                    $AffinityDisplay = "$CurrentAffinity (0x{0:X8})" -f $CurrentAffinity
                    $CurrentSelectedCores = Convert-AffinityMaskToCoreList -AffinityMask $CurrentAffinity
                }
            }
            $GPUPriorityValue = Get-ItemProperty -LiteralPath $RegPath -Name "GPU Priority" -ErrorAction SilentlyContinue
            if ($null -ne $GPUPriorityValue) {
                $CurrentGPUPriority = [int]$GPUPriorityValue.'GPU Priority'
            }
            $CPUPriorityValue = Get-ItemProperty -LiteralPath $RegPath -Name "Priority" -ErrorAction SilentlyContinue
            if ($null -ne $CPUPriorityValue) {
                $CurrentCPUPriority = [int]$CPUPriorityValue.Priority
            }
        }
        catch {
            Write-Warning "Chyba při načítání hodnot z registry: $($_.Exception.Message)"
        }
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host "     ÚPRAVA AUDIO PROFILU (MMCSS)                          " -ForegroundColor Green
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
        [int]$TotalCoresDisplay = 0
        try {
            $TotalCoresDisplay = [int]$env:NUMBER_OF_PROCESSORS
        }
        catch {
            $TotalCoresDisplay = 8
        }
        Write-Host "Informace o systému:" -ForegroundColor Cyan
        Write-Host "  CPU Jader celkem: $TotalCoresDisplay (indexováno 0-$($TotalCoresDisplay - 1))" -ForegroundColor White
        Show-CPUTopology -Threads $TotalCoresDisplay -HighlightCores $CurrentSelectedCores
        Write-Host "Podporované formáty pro CPU Afinitu:" -ForegroundColor Cyan
        Write-Host "  • 'posledni X'  → Posledních X jader (např. 'posledni 2')" -ForegroundColor Gray
        Write-Host "  • 'prvni X'     → Prvních X jader (např. 'prvni 4')" -ForegroundColor Gray
        Write-Host "  • 'X-Y'         → Rozsah jader (např. '0-7')" -ForegroundColor Gray
        Write-Host "  • 'X,Y,Z'       → Seznam jader (např. '2,4,6,8')" -ForegroundColor Gray
        Write-Host "  • 'X'           → Jedno jádro (např. '5')" -ForegroundColor Gray
        Write-Host "  • 'vsechny'     → Bez afinity (systém řídí sám) [DOPORUČENO]" -ForegroundColor Gray
        Write-Host ""
        Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Aktuální nastavení:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  [1] CPU Afinita       : $AffinityDisplay" -ForegroundColor Cyan
        Write-Host "      → Která CPU jádra může proces použít" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [2] GPU Priorita (1-8): $CurrentGPUPriority" -ForegroundColor Cyan
        Write-Host "      → Vyšší = více GPU času (8 = maximum)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [3] CPU Priorita (1-8): $CurrentCPUPriority" -ForegroundColor Cyan
        Write-Host "      → Vyšší = více CPU času (6 = doporučeno pro audio)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [4] Aplikovat Doporučený Audio Profil (OEM/Default)" -ForegroundColor Yellow
        Write-Host "      → Affinity=0, GPU Priority=8, CPU Priority=6" -ForegroundColor Gray
        Write-Host "      → Background Only=True, Scheduling=Medium, SFIO=Normal" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [B] Zpět do Předchozího Menu" -ForegroundColor Red
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
        $choice = Read-Host -Prompt "Zadejte svou volbu"
        switch ($choice) {
            '1' {
                Write-Host ""
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host "  NASTAVENÍ CPU AFINITY" -ForegroundColor Yellow
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host ""
                [int]$TotalCores = 0
                try {
                    $TotalCores = [int]$env:NUMBER_OF_PROCESSORS
                    Write-Host "Váš systém má $TotalCores logických procesorů (jádra 0 až $($TotalCores - 1))" -ForegroundColor White
                }
                catch {
                    Write-Warning "Nepodařilo se detekovat počet CPU jader."
                    $TotalCores = 8
                }
                Write-Host ""
                Write-Host "Podporované formáty:" -ForegroundColor Yellow
                Write-Host "  • 'posledni X'  - Posledních X jader (např. 'posledni 2')" -ForegroundColor Gray
                Write-Host "  • 'prvni X'     - Prvních X jader (např. 'prvni 4')" -ForegroundColor Gray
                Write-Host "  • 'X-Y'         - Rozsah jader (např. '0-7')" -ForegroundColor Gray
                Write-Host "  • 'X'           - Jedno jádro (např. '5')" -ForegroundColor Gray
                Write-Host "  • 'vsechny'     - Bez afinity (systém řídí sám) [DOPORUČENO]" -ForegroundColor Gray
                Write-Host ""
                $selectedStrategy = Select-AffinityStrategy
                $suggestion = Get-SmartAffinitySuggestion -ProfileType 'Audio' -Strategy $selectedStrategy
                Write-Host "💡 INTELIGENTNÍ DOPORUČENÍ:" -ForegroundColor Cyan
                Write-Host "   $($suggestion.Description)" -ForegroundColor Yellow
                Write-Host "   → Zadejte: '$($suggestion.RecommendedInput)'" -ForegroundColor Green
                Write-Host "   ℹ️  $($suggestion.Reason)" -ForegroundColor Gray
                if ($null -ne $suggestion.AlternativeInput) {
                    Write-Host ""
                    Write-Host "   Alternativa: $($suggestion.AlternativeDesc)" -ForegroundColor Cyan
                    Write-Host "   → '$($suggestion.AlternativeInput)'" -ForegroundColor Gray
                }
                if ($suggestion.SafetyLevel -eq "EXPERIMENTAL") {
                    Write-Host ""
                    Write-Host "   ⚠️  ÚROVEŇ: EXPERIMENTÁLNÍ" -ForegroundColor Red
                }
                elseif ($suggestion.SafetyLevel -eq "SAFE") {
                    Write-Host ""
                    Write-Host "   ✅ ÚROVEŇ: BEZPEČNÉ" -ForegroundColor Green
                }
                Write-Host ""
                $InputAffinity = Read-Host "Zadejte afinitu"
                $AffinityResult = Get-AffinityMask -CoreRange $InputAffinity
                if ($null -ne $AffinityResult) {
                    # Use Invoke-RegistryOperation for auto-backup & privilege escalation
                    $regResult = Invoke-RegistryOperation `
                        -Path $RegPath `
                        -Name "Affinity" `
                        -Value $AffinityResult.HodnotaDecimal `
                        -Type DWord
                    if ($regResult.Success) {
                        Write-Host ""
                        Write-Host "CPU Afinita úspěšně nastavena na: $($AffinityResult.HodnotaDecimal) ($($AffinityResult.RegEditFormat))" -ForegroundColor Green
                        Write-Host "Pro obnovení na OEM výchozí hodnoty použijte volbu [3] Obnovit v hlavním menu." -ForegroundColor Gray
                        if ($AffinityResult.HodnotaDecimal -gt 0) {
                            Write-Host ""
                            Write-Host "Vybraná jádra (zvýrazněna žlutě):" -ForegroundColor Yellow
                            $SelectedCoresList = Convert-AffinityMaskToCoreList -AffinityMask $AffinityResult.HodnotaDecimal
                            Show-CPUTopology -Threads $TotalCores -HighlightCores $SelectedCoresList
                        }
                        else {
                            Write-Host ""
                            Write-Host "Afinita nastavena na 0 - systém bude řízení jader řídit sám." -ForegroundColor Cyan
                        }
                    }
                    else {
                        Write-Error "Chyba při aplikaci CPU afinity: $($regResult.Error)"
                    }
                }
                else {
                    Write-Warning "Neplatný vstup. Afinita nebyla změněna."
                }
                Write-Host ""
                Write-Host "Stiskněte klávesu pro pokračování..." -ForegroundColor White
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '2' {
                Write-Host ""
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host "  NASTAVENÍ GPU PRIORITY" -ForegroundColor Yellow
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "GPU Priorita určuje, kolik GPU času dostane proces." -ForegroundColor Gray
                Write-Host "Rozsah: 1-8 (8 = maximum, může být užitečné pro GPU-akcelerované efekty)" -ForegroundColor Gray
                Write-Host ""
                $InputGPUPriority = Read-Host "Zadejte GPU Prioritu (1-8, doporučeno 8)"
                [int]$NewGPUPriority = 0
                if ([int]::TryParse($InputGPUPriority, [ref]$NewGPUPriority)) {
                    if ($NewGPUPriority -ge 1 -and $NewGPUPriority -le 8) {
                        # Use Invoke-RegistryOperation for auto-backup & privilege escalation
                        $regResult = Invoke-RegistryOperation `
                            -Path $RegPath `
                            -Name "GPU Priority" `
                            -Value $NewGPUPriority `
                            -Type DWord
                        if ($regResult.Success) {
                            Write-Host ""
                            Write-Host "GPU Priorita úspěšně nastavena na: $NewGPUPriority" -ForegroundColor Green
                            Write-Host "Pro obnovení na OEM výchozí hodnoty použijte volbu [3] Obnovit v hlavním menu." -ForegroundColor Gray
                        }
                        else {
                            Write-Error "Chyba při aplikaci GPU priority: $($regResult.Error)"
                        }
                    }
                    else {
                        Write-Warning "Neplatná hodnota. Musí být celé číslo od 1 do 8."
                    }
                }
                else {
                    Write-Warning "Neplatný vstup. GPU Priorita nebyla změněna."
                }
                Write-Host ""
                Write-Host "Stiskněte klávesu pro pokračování..." -ForegroundColor White
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '3' {
                Write-Host ""
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host "  NASTAVENÍ CPU PRIORITY" -ForegroundColor Yellow
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "CPU Priorita určuje, kolik CPU času dostane proces." -ForegroundColor Gray
                Write-Host "Rozsah: 1-8 (6 = doporučeno pro audio, 8 = maximum)" -ForegroundColor Gray
                Write-Host ""
                $InputCPUPriority = Read-Host "Zadejte CPU Prioritu (1-8, doporučeno 6)"
                [int]$NewCPUPriority = 0
                if ([int]::TryParse($InputCPUPriority, [ref]$NewCPUPriority)) {
                    if ($NewCPUPriority -ge 1 -and $NewCPUPriority -le 8) {
                        # Use Invoke-RegistryOperation for auto-backup & privilege escalation
                        $regResult = Invoke-RegistryOperation `
                            -Path $RegPath `
                            -Name "Priority" `
                            -Value $NewCPUPriority `
                            -Type DWord
                        if ($regResult.Success) {
                            Write-Host ""
                            Write-Host "CPU Priorita úspěšně nastavena na: $NewCPUPriority" -ForegroundColor Green
                            Write-Host "Pro obnovení na OEM výchozí hodnoty použijte volbu [3] Obnovit v hlavním menu." -ForegroundColor Gray
                        }
                        else {
                            Write-Error "Chyba při aplikaci CPU priority: $($regResult.Error)"
                        }
                    }
                    else {
                        Write-Warning "Neplatná hodnota. Musí být celé číslo od 1 do 8."
                    }
                }
                else {
                    Write-Warning "Neplatný vstup. CPU Priorita nebyla změněna."
                }
                Write-Host ""
                Write-Host "Stiskněte klávesu pro pokračování..." -ForegroundColor White
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '4' {
                Write-Host ""
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host "  APLIKACE DOPORUČENÉHO AUDIO PROFILU (OEM/Default)" -ForegroundColor Yellow
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Tento profil nastaví optimální hodnoty pro audio aplikace:" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  • Affinity = 0 (Bez afinity - systém řídí)" -ForegroundColor White
                Write-Host "  • GPU Priority = 8 (Maximum)" -ForegroundColor White
                Write-Host "  • Priority = 6 (Doporučeno pro audio)" -ForegroundColor White
                Write-Host "  • Clock Rate = 10000 (0x2710)" -ForegroundColor White
                Write-Host "  • Background Only = True (ROZDÍL oproti Games!)" -ForegroundColor Yellow
                Write-Host "  • Scheduling Category = Medium (ROZDÍL oproti Games!)" -ForegroundColor Yellow
                Write-Host "  • SFIO Priority = Normal (ROZDÍL oproti Games!)" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "POZNÁMKA: Audio profil NEMÁ 'IO Priority' (na rozdíl od Games)" -ForegroundColor Gray
                Write-Host ""
                $Confirm = Read-Host "Aplikovat doporučený audio profil? (A/N)"
                if ($Confirm -eq 'A' -or $Confirm -eq 'a') {
                    # Use Invoke-RegistryOperation for auto-backup & privilege escalation
                    $allSuccess = $true
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "Affinity" -Value 0x00000000 -Type DWord
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "Affinity: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "GPU Priority" -Value 0x00000008 -Type DWord
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "GPU Priority: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "Priority" -Value 0x00000006 -Type DWord
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "Priority: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "Clock Rate" -Value 0x00002710 -Type DWord
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "Clock Rate: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "Background Only" -Value "True" -Type String
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "Background Only: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "Scheduling Category" -Value "Medium" -Type String
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "Scheduling Category: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "SFIO Priority" -Value "Normal" -Type String
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "SFIO Priority: $($result.Error)" }
                    if ($allSuccess) {
                        Write-Host ""
                        Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
                        Write-Host "║  DOPORUČENÝ AUDIO PROFIL ÚSPĚŠNĚ APLIKOVÁN!               ║" -ForegroundColor Green
                        Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
                        Write-Host ""
                        Write-Host "Aplikovány OEM výchozí hodnoty pro audio profil." -ForegroundColor Gray
                        Write-Host ""
                        Write-Host "DOPORUČENÍ:" -ForegroundColor Yellow
                        Write-Host "  • Pro úplné použití změn restartujte audio aplikace/DAW" -ForegroundColor Gray
                        Write-Host "  • Některé změny mohou vyžadovat restart systému" -ForegroundColor Gray
                        Write-Host "  • Pro obnovení použijte volbu [3] Obnovit v hlavním menu" -ForegroundColor Gray
                    }
                    else {
                        Write-Error "Chyba při aplikaci doporučeného audio profilu. Zkontrolujte výše uvedená varování."
                    }
                }
                else {
                    Write-Host "Operace zrušena." -ForegroundColor Yellow
                }
                Write-Host ""
                Write-Host "Stiskněte klávesu pro pokračování..." -ForegroundColor White
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            'B' { return }
            'b' { return }
            default {
                Write-Warning "Neplatná volba. Zadejte 1, 2, 3, 4 nebo B."
                Start-Sleep -Seconds 2
            }
        }
    }
}
function Edit-DisplayPostProcessingProfile {
    <#
    .SYNOPSIS
        Interactive editor for MMCSS DisplayPostProcessing profile.
    #>
    [CmdletBinding()]
    param()
    [string]$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\DisplayPostProcessing"
    if (-not (Test-Path -LiteralPath $RegPath)) {
        Write-Host ""
        Write-Host "Registry klíč pro DisplayPostProcessing profil neexistuje. Vytvářím..." -ForegroundColor Yellow
        try {
            New-Item -Path $RegPath -Force -ErrorAction Stop | Out-Null
            Write-Host "Registry klíč úspěšně vytvořen: $RegPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Nepodařilo se vytvořit registry klíč: $($_.Exception.Message)"
            Write-Host "Stiskněte klávesu pro návrat..." -ForegroundColor Red
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }
    }
    while ($true) {
        Clear-Host
        [int]$CurrentAffinity = 0
        [int]$CurrentBackgroundPriority = 0
        [int]$CurrentGPUPriority = 0
        [int]$CurrentCPUPriority = 0
        [string]$AffinityDisplay = "Nenastaveno"
        [array]$CurrentSelectedCores = @()
        try {
            $AffinityValue = Get-ItemProperty -LiteralPath $RegPath -Name "Affinity" -ErrorAction SilentlyContinue
            if ($null -ne $AffinityValue) {
                $CurrentAffinity = [int]$AffinityValue.Affinity
                if ($CurrentAffinity -eq 0) {
                    $AffinityDisplay = "0 (Bez afinity - systém řídí)"
                    $CurrentSelectedCores = @()
                }
                else {
                    $AffinityDisplay = "$CurrentAffinity (0x{0:X8})" -f $CurrentAffinity
                    $CurrentSelectedCores = Convert-AffinityMaskToCoreList -AffinityMask $CurrentAffinity
                }
            }
            $BackgroundPriorityValue = Get-ItemProperty -LiteralPath $RegPath -Name "BackgroundPriority" -ErrorAction SilentlyContinue
            if ($null -ne $BackgroundPriorityValue) {
                $CurrentBackgroundPriority = [int]$BackgroundPriorityValue.BackgroundPriority
            }
            $GPUPriorityValue = Get-ItemProperty -LiteralPath $RegPath -Name "GPU Priority" -ErrorAction SilentlyContinue
            if ($null -ne $GPUPriorityValue) {
                $CurrentGPUPriority = [int]$GPUPriorityValue.'GPU Priority'
            }
            $CPUPriorityValue = Get-ItemProperty -LiteralPath $RegPath -Name "Priority" -ErrorAction SilentlyContinue
            if ($null -ne $CPUPriorityValue) {
                $CurrentCPUPriority = [int]$CPUPriorityValue.Priority
            }
        }
        catch {
            Write-Warning "Chyba při načítání hodnot z registry: $($_.Exception.Message)"
        }
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host "     ÚPRAVA DISPLAYPOSTPROCESSING PROFILU (MMCSS)          " -ForegroundColor Green
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
        Write-Host "POZNÁMKA: Tento profil je systémem využíván zřídka." -ForegroundColor Gray
        Write-Host "          Primárně pro DWM a grafické kompozitní efekty." -ForegroundColor Gray
        Write-Host ""
        [int]$TotalCoresDisplay = 0
        try {
            $TotalCoresDisplay = [int]$env:NUMBER_OF_PROCESSORS
        }
        catch {
            $TotalCoresDisplay = 8
        }
        Write-Host "Informace o systému:" -ForegroundColor Cyan
        Write-Host "  CPU Jader celkem: $TotalCoresDisplay (indexováno 0-$($TotalCoresDisplay - 1))" -ForegroundColor White
        Show-CPUTopology -Threads $TotalCoresDisplay -HighlightCores $CurrentSelectedCores
        Write-Host "Podporované formáty pro CPU Afinitu:" -ForegroundColor Cyan
        Write-Host "  • 'posledni X'  → Posledních X jader (např. 'posledni 2')" -ForegroundColor Gray
        Write-Host "  • 'prvni X'     → Prvních X jader (např. 'prvni 4')" -ForegroundColor Gray
        Write-Host "  • 'X-Y'         → Rozsah jader (např. '0-7')" -ForegroundColor Gray
        Write-Host "  • 'X,Y,Z'       → Seznam jader (např. '2,4,6,8')" -ForegroundColor Gray
        Write-Host "  • 'X'           → Jedno jádro (např. '5')" -ForegroundColor Gray
        Write-Host "  • 'vsechny'     → Bez afinity (systém řídí sám) [DOPORUČENO]" -ForegroundColor Gray
        Write-Host ""
        Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host ""
        Write-Host "Aktuální nastavení:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  [1] CPU Afinita             : $AffinityDisplay" -ForegroundColor Cyan
        Write-Host "      → Která CPU jádra může proces použít" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [2] Background Priorita (1-8): $CurrentBackgroundPriority" -ForegroundColor Cyan
        Write-Host "      → Speciální hodnota pro tento profil (doporučeno 8)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [3] GPU Priorita (1-8)      : $CurrentGPUPriority" -ForegroundColor Cyan
        Write-Host "      → Vyšší = více GPU času (doporučeno 8)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [4] CPU Priorita (1-8)      : $CurrentCPUPriority" -ForegroundColor Cyan
        Write-Host "      → Vyšší = více CPU času (doporučeno 8)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [5] Aplikovat Doporučený DPP Profil (OEM/Default)" -ForegroundColor Yellow
        Write-Host "      → Affinity=0, BackgroundPriority=8, GPU Priority=8, CPU Priority=8" -ForegroundColor Gray
        Write-Host "      → Background Only=True, Scheduling=High, SFIO=High" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [B] Zpět do Předchozího Menu" -ForegroundColor Red
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
        $choice = Read-Host -Prompt "Zadejte svou volbu"
        switch ($choice) {
            '1' {
                Write-Host ""
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host "  NASTAVENÍ CPU AFINITY" -ForegroundColor Yellow
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host ""
                [int]$TotalCores = 0
                try {
                    $TotalCores = [int]$env:NUMBER_OF_PROCESSORS
                    Write-Host "Váš systém má $TotalCores logických procesorů (jádra 0 až $($TotalCores - 1))" -ForegroundColor White
                }
                catch {
                    Write-Warning "Nepodařilo se detekovat počet CPU jader."
                    $TotalCores = 8
                }
                Write-Host ""
                Write-Host "Podporované formáty:" -ForegroundColor Yellow
                Write-Host "  • 'posledni X'  - Posledních X jader (např. 'posledni 2')" -ForegroundColor Gray
                Write-Host "  • 'prvni X'     - Prvních X jader (např. 'prvni 4')" -ForegroundColor Gray
                Write-Host "  • 'X-Y'         - Rozsah jader (např. '0-7')" -ForegroundColor Gray
                Write-Host "  • 'X'           - Jedno jádro (např. '5')" -ForegroundColor Gray
                Write-Host "  • 'vsechny'     - Bez afinity (systém říd sám) [DOPORUČENO]" -ForegroundColor Gray
                Write-Host ""
                $suggestion = Get-SmartAffinitySuggestion -ProfileType 'DisplayPostProcessing'
                Write-Host "💡 INTELIGENTNÍ DOPORUČENÍ:" -ForegroundColor Cyan
                Write-Host "   $($suggestion.Description)" -ForegroundColor Yellow
                Write-Host "   → Zadejte: '$($suggestion.RecommendedInput)'" -ForegroundColor Green
                Write-Host "   ℹ️  $($suggestion.Reason)" -ForegroundColor Gray
                Write-Host ""
                $InputAffinity = Read-Host "Zadejte afinitu"
                $AffinityResult = Get-AffinityMask -CoreRange $InputAffinity
                if ($null -ne $AffinityResult) {
                    # Use Invoke-RegistryOperation for auto-backup & privilege escalation
                    $regResult = Invoke-RegistryOperation `
                        -Path $RegPath `
                        -Name "Affinity" `
                        -Value $AffinityResult.HodnotaDecimal `
                        -Type DWord
                    if ($regResult.Success) {
                        Write-Host ""
                        Write-Host "CPU Afinita úspěšně nastavena na: $($AffinityResult.HodnotaDecimal) ($($AffinityResult.RegEditFormat))" -ForegroundColor Green
                        Write-Host "Pro obnovení na OEM výchozí hodnoty použijte volbu [4] Obnovit v hlavním menu." -ForegroundColor Gray
                        if ($AffinityResult.HodnotaDecimal -gt 0) {
                            Write-Host ""
                            Write-Host "Vybraná jádra (zvýrazněna žlutě):" -ForegroundColor Yellow
                            $SelectedCoresList = Convert-AffinityMaskToCoreList -AffinityMask $AffinityResult.HodnotaDecimal
                            Show-CPUTopology -Threads $TotalCores -HighlightCores $SelectedCoresList
                        }
                        else {
                            Write-Host ""
                            Write-Host "Afinita nastavena na 0 - systém bude řízení jader řídit sám." -ForegroundColor Cyan
                        }
                    }
                    else {
                        Write-Error "Chyba při aplikaci CPU afinity: $($regResult.Error)"
                    }
                }
                else {
                    Write-Warning "Neplatný vstup. Afinita nebyla změněna."
                }
                Write-Host ""
                Write-Host "Stiskněte klávesu pro pokračování..." -ForegroundColor White
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '2' {
                Write-Host ""
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host "  NASTAVENÍ BACKGROUND PRIORITY" -ForegroundColor Yellow
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Background Priorita je speciální hodnota pro DisplayPostProcessing." -ForegroundColor Gray
                Write-Host "Rozsah: 1-8 (8 = maximum)" -ForegroundColor Gray
                Write-Host ""
                $InputBgPriority = Read-Host "Zadejte Background Prioritu (1-8, doporučeno 8)"
                [int]$NewBgPriority = 0
                if ([int]::TryParse($InputBgPriority, [ref]$NewBgPriority)) {
                    if ($NewBgPriority -ge 1 -and $NewBgPriority -le 8) {
                        # Use Invoke-RegistryOperation for auto-backup & privilege escalation
                        $regResult = Invoke-RegistryOperation `
                            -Path $RegPath `
                            -Name "BackgroundPriority" `
                            -Value $NewBgPriority `
                            -Type DWord
                        if ($regResult.Success) {
                            Write-Host ""
                            Write-Host "Background Priorita úspěšně nastavena na: $NewBgPriority" -ForegroundColor Green
                            Write-Host "Pro obnovení na OEM výchozí hodnoty použijte volbu [4] Obnovit v hlavním menu." -ForegroundColor Gray
                        }
                        else {
                            Write-Error "Chyba při aplikaci Background priority: $($regResult.Error)"
                        }
                    }
                    else {
                        Write-Warning "Neplatná hodnota. Musí být celé číslo od 1 do 8."
                    }
                }
                else {
                    Write-Warning "Neplatný vstup. Background Priorita nebyla změněna."
                }
                Write-Host ""
                Write-Host "Stiskněte klávesu pro pokračování..." -ForegroundColor White
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '3' {
                Write-Host ""
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host "  NASTAVENÍ GPU PRIORITY" -ForegroundColor Yellow
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "GPU Priorita určuje, kolik GPU času dostane proces." -ForegroundColor Gray
                Write-Host "Rozsah: 1-8 (8 = maximum)" -ForegroundColor Gray
                Write-Host ""
                $InputGPUPriority = Read-Host "Zadejte GPU Prioritu (1-8, doporučeno 8)"
                [int]$NewGPUPriority = 0
                if ([int]::TryParse($InputGPUPriority, [ref]$NewGPUPriority)) {
                    if ($NewGPUPriority -ge 1 -and $NewGPUPriority -le 8) {
                        # Use Invoke-RegistryOperation for auto-backup & privilege escalation
                        $regResult = Invoke-RegistryOperation `
                            -Path $RegPath `
                            -Name "GPU Priority" `
                            -Value $NewGPUPriority `
                            -Type DWord
                        if ($regResult.Success) {
                            Write-Host ""
                            Write-Host "GPU Priorita úspěšně nastavena na: $NewGPUPriority" -ForegroundColor Green
                            Write-Host "Pro obnovení na OEM výchozí hodnoty použijte volbu [4] Obnovit v hlavním menu." -ForegroundColor Gray
                        }
                        else {
                            Write-Error "Chyba při aplikaci GPU priority: $($regResult.Error)"
                        }
                    }
                    else {
                        Write-Warning "Neplatná hodnota. Musí být celé číslo od 1 do 8."
                    }
                }
                else {
                    Write-Warning "Neplatný vstup. GPU Priorita nebyla změněna."
                }
                Write-Host ""
                Write-Host "Stiskněte klávesu pro pokračování..." -ForegroundColor White
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '4' {
                Write-Host ""
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host "  NASTAVENÍ CPU PRIORITY" -ForegroundColor Yellow
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "CPU Priorita určuje, kolik CPU času dostane proces." -ForegroundColor Gray
                Write-Host "Rozsah: 1-8 (8 = doporučeno pro DisplayPostProcessing)" -ForegroundColor Gray
                Write-Host ""
                $InputCPUPriority = Read-Host "Zadejte CPU Prioritu (1-8, doporučeno 8)"
                [int]$NewCPUPriority = 0
                if ([int]::TryParse($InputCPUPriority, [ref]$NewCPUPriority)) {
                    if ($NewCPUPriority -ge 1 -and $NewCPUPriority -le 8) {
                        # Use Invoke-RegistryOperation for auto-backup & privilege escalation
                        $regResult = Invoke-RegistryOperation `
                            -Path $RegPath `
                            -Name "Priority" `
                            -Value $NewCPUPriority `
                            -Type DWord
                        if ($regResult.Success) {
                            Write-Host ""
                            Write-Host "CPU Priorita úspěšně nastavena na: $NewCPUPriority" -ForegroundColor Green
                            Write-Host "Pro obnovení na OEM výchozí hodnoty použijte volbu [4] Obnovit v hlavním menu." -ForegroundColor Gray
                        }
                        else {
                            Write-Error "Chyba při aplikaci CPU priority: $($regResult.Error)"
                        }
                    }
                    else {
                        Write-Warning "Neplatná hodnota. Musí být celé číslo od 1 do 8."
                    }
                }
                else {
                    Write-Warning "Neplatný vstup. CPU Priorita nebyla změněna."
                }
                Write-Host ""
                Write-Host "Stiskněte klávesu pro pokračování..." -ForegroundColor White
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '5' {
                Write-Host ""
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host "  APLIKACE DOPORUČENÉHO DPP PROFILU (OEM/Default)" -ForegroundColor Yellow
                Write-Host "───────────────────────────────────────────────────────────" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "Tento profil nastaví optimální hodnoty pro DisplayPostProcessing:" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  • Affinity = 0 (Bez afinity)" -ForegroundColor White
                Write-Host "  • BackgroundPriority = 8" -ForegroundColor White
                Write-Host "  • GPU Priority = 8" -ForegroundColor White
                Write-Host "  • Priority = 8" -ForegroundColor White
                Write-Host "  • Clock Rate = 10000 (0x2710)" -ForegroundColor White
                Write-Host "  • Background Only = True" -ForegroundColor White
                Write-Host "  • Scheduling Category = High" -ForegroundColor White
                Write-Host "  • SFIO Priority = High" -ForegroundColor White
                Write-Host ""
                $Confirm = Read-Host "Aplikovat doporučený DPP profil? (A/N)"
                if ($Confirm -eq 'A' -or $Confirm -eq 'a') {
                    # Use Invoke-RegistryOperation for auto-backup & privilege escalation
                    $allSuccess = $true
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "Affinity" -Value 0x00000000 -Type DWord
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "Affinity: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "BackgroundPriority" -Value 0x00000008 -Type DWord
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "BackgroundPriority: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "Clock Rate" -Value 0x00002710 -Type DWord
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "Clock Rate: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "GPU Priority" -Value 0x00000008 -Type DWord
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "GPU Priority: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "Priority" -Value 0x00000008 -Type DWord
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "Priority: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "Background Only" -Value "True" -Type String
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "Background Only: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "Scheduling Category" -Value "High" -Type String
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "Scheduling Category: $($result.Error)" }
                    $result = Invoke-RegistryOperation -Path $RegPath -Name "SFIO Priority" -Value "High" -Type String
                    if (-not $result.Success) { $allSuccess = $false; Write-Warning "SFIO Priority: $($result.Error)" }
                    if ($allSuccess) {
                        Write-Host ""
                        Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
                        Write-Host "║  DOPORUČENÝ DPP PROFIL ÚSPĚŠNĚ APLIKOVÁN!                 ║" -ForegroundColor Green
                        Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
                        Write-Host ""
                        Write-Host "Aplikovány OEM výchozí hodnoty pro DisplayPostProcessing profil." -ForegroundColor Gray
                        Write-Host ""
                        Write-Host "DOPORUČENÍ:" -ForegroundColor Yellow
                        Write-Host "  • Restart systému může být nutný pro úplné použití změn" -ForegroundColor Gray
                        Write-Host "  • Pro obnovení použijte volbu [4] Obnovit v hlavním menu" -ForegroundColor Gray
                    }
                    else {
                        Write-Error "Chyba při aplikaci doporučeného DPP profilu. Zkontrolujte výše uvedená varování."
                    }
                }
                else {
                    Write-Host "Operace zrušena." -ForegroundColor Yellow
                }
                Write-Host ""
                Write-Host "Stiskněte klávesu pro pokračování..." -ForegroundColor White
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            'B' { return }
            'b' { return }
            default {
                Write-Warning "Neplatná volba. Zadejte 1, 2, 3, 4, 5 nebo B."
                Start-Sleep -Seconds 2
            }
        }
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
    Show-GameAudioPriorityMenu
}
Export-ModuleMember -Function @(
    'Show-GameAudioPriorityMenu'
    'Edit-GameProfile'
    'Edit-AudioProfile'
    'Edit-DisplayPostProcessingProfile'
    'Restore-MMCSSDefaults'
    'Invoke-ModuleEntry'
)