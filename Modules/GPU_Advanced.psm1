# ===========================================================
# Modul: GPU_Advanced.psm1
# Popis: Pokročilé GPU funkce - Univerzální pro všechny výrobce
# Autor: KRAKE-FIX Team
# Projekt: KRAKE-FIX v2 Modular
# ===========================================================
# ⚠️ Tento modul může měnit systémové nastavení.
# Používej pouze ve studijním / testovacím prostředí.
# Autor neručí za zneužití mimo akademické účely.
# ===========================================================

#Requires -Version 5.1
#Requires -RunAsAdministrator

# Import Core modulu pro privilege management
# Use Core module functions - loaded by Main.ps1, only import if standalone
if (-not (Get-Command Write-CoreLog -ErrorAction SilentlyContinue)) {
    $CoreModule = Join-Path $PSScriptRoot 'Core.psm1'
    if (Test-Path $CoreModule) {
        Import-Module $CoreModule -Force -ErrorAction Stop
    }
}

# ===========================================================
# MODULE-LEVEL VARIABLES
# ===========================================================

$script:ModuleName = 'GPU_Advanced'
$script:ModuleVersion = '2.0.0'
$script:LogPath = Join-Path $env:TEMP "KRAKE-FIX-$script:ModuleName.log"

# Dokumentace cesty
$script:DocPath = Join-Path (Split-Path $PSScriptRoot -Parent) "NastrojTemp\gpu"

# ===========================================================
# ADVANCED GPU FEATURES MENU
# ===========================================================

<#
.SYNOPSIS
    Pokročilé GPU funkce - Univerzální pro všechny výrobce.

.DESCRIPTION
    Zobrazuje menu s pokročilými funkcemi, které fungují univerzálně:
      [H] Hardware GPU Scheduling (HAGS) - ON/OFF
      [G] Windows Herní režim - ON/OFF
      [R] Resizable BAR - Info + Check
      [i] Info o pokročilých funkcích
      [Q] Zpět

.NOTES
    Tyto funkce jsou univerzální a fungují pro NVIDIA, AMD i Intel.
    Vyžadují restart PC pro aktivaci.
#>
function Show-AdvancedGpuMenu {
    while ($true) {
        Clear-Host
        Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Magenta
        Write-Host "        🔧 POKROČILÉ GPU FUNKCE - UNIVERZÁLNÍ             " -ForegroundColor Magenta
        Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "Tyto funkce fungují pro NVIDIA, AMD i Intel GPU." -ForegroundColor Gray
        Write-Host ""
        
        # Zjistit aktuální stav HAGS
        $hagsStatus = Get-HagsStatus
        $hagsColor = if ($hagsStatus -eq "Zapnuto") { "Green" } else { "Yellow" }
        
        # Zjistit aktuální stav Herního režimu
        $gameModeStatus = Get-GameModeStatus
        $gameModeColor = if ($gameModeStatus -eq "Zapnuto") { "Green" } else { "Yellow" }
        
        Write-Host "──────────────────────────────────────────────────────────"
        Write-Host "[H] ⚡ HARDWARE GPU SCHEDULING (HAGS)" -ForegroundColor Cyan
        Write-Host "    Aktuální stav: $hagsStatus" -ForegroundColor $hagsColor
        Write-Host "    ✅ Přínosy: Input lag -1-3ms, lepší frame pacing" -ForegroundColor Green
        Write-Host "    ⚠️  Rizika: Vyžaduje RTX 20xx+ / RX 6xxx+ pro benefit" -ForegroundColor DarkYellow
        Write-Host ""
        
        Write-Host "[G] 🎮 WINDOWS HERNÍ REŽIM" -ForegroundColor Cyan
        Write-Host "    Aktuální stav: $gameModeStatus" -ForegroundColor $gameModeColor
        Write-Host "    ✅ Přínosy: Prioritizuje hru, vypíná update na pozadí" -ForegroundColor Green
        Write-Host "    ⚠️  Rizika: Může ovlivnit multi-tasking" -ForegroundColor DarkYellow
        Write-Host ""
        
        Write-Host "[R] 📊 RESIZABLE BAR (SAM) - INFO & CHECK" -ForegroundColor Cyan
        Write-Host "    Zkontroluje zda máte ReBAR zapnutý (RTX 30xx+/RX 6xxx+)" -ForegroundColor Gray
        Write-Host ""
        
        # Zjistit aktuální stav MPO
        $mpoStatus = Get-MpoStatus
        $mpoColor = if ($mpoStatus -eq "Zakázáno") { "Green" } else { "Yellow" }
        
        Write-Host "[M] 🚫 MPO (MULTI-PLANE OVERLAY)" -ForegroundColor Cyan
        Write-Host "    Aktuální stav: $mpoStatus" -ForegroundColor $mpoColor
        Write-Host "    ✅ Přínosy: Oprava black screenů, flickeringu" -ForegroundColor Green
        Write-Host "    ⚠️  Rizika: Žádná (doporučeno zakázat)" -ForegroundColor Green
        Write-Host ""
        
        Write-Host "──────────────────────────────────────────────────────────"
        Write-Host "[i] ℹ️  INFO O POKROČILÝCH FUNKCÍCH" -ForegroundColor White
        Write-Host ""
        
        Write-Host "[Q] ⬅️  ZPĚT DO GPU MENU" -ForegroundColor Red
        Write-Host "══════════════════════════════════════════════════════════"
        Write-Host ""
        
        $choice = Read-Host -Prompt "Zadejte svou volbu"
        
        switch ($choice.ToUpper()) {
            'H' { Show-HagsToggleMenu }
            'G' { Show-GameModeToggleMenu }
            'R' { Show-ResizableBarInfo }
            'M' { Show-MpoToggleMenu }
            'I' { Show-AdvancedGpuInfo }
            'Q' { return }
            default { 
                Write-Warning "Neplatná volba. Zkuste to znovu."
                Start-Sleep 2
            }
        }
    }
}

# ===========================================================
# MPO (MULTI-PLANE OVERLAY) DISABLE - UNIVERZÁLNÍ
# ===========================================================

<#
.SYNOPSIS
    Zjistí aktuální stav MPO (Multi-Plane Overlay).
    
.OUTPUTS
    String: "Zakázáno" nebo "Povoleno"
#>
function Get-MpoStatus {
    try {
        $mpo = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" -Name "OverlayTestMode" -ErrorAction SilentlyContinue
        if ($mpo.OverlayTestMode -eq 5) {
            return "Zakázáno"
        } else {
            return "Povoleno"
        }
    } catch {
        return "Povoleno (výchozí)"
    }
}

<#
.SYNOPSIS
    Zakáže MPO (Multi-Plane Overlay) pro všechny GPU.
    
.DESCRIPTION
    MPO je funkce Windows DWM, která často způsobuje problémy:
      - Náhodné černé obrazovky (black screens)
      - Blikání obrazovky (flickering)
      - Stuttering v prohlížečích (YouTube, Twitch)
      - Multi-monitor problémy
      
    Tento tweak je UNIVERZÁLNÍ - funguje pro NVIDIA, AMD i Intel.
    
.NOTES
    Vyžaduje restart PC pro aktivaci.
    Používá Invoke-RegistryOperation pro bezpečné zálohování.
#>
function Invoke-DisableMPO {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host "  🚫 MPO (MULTI-PLANE OVERLAY) - ZAKÁZAT"
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""
    
    $currentStatus = Get-MpoStatus
    Write-Host "Aktuální stav MPO: $currentStatus" -ForegroundColor $(if ($currentStatus -eq "Zakázáno") { "Green" } else { "Yellow" })
    Write-Host ""
    
    if ($currentStatus -eq "Zakázáno") {
        Write-Host "✅ MPO je již zakázáno. Není nutná žádná změna." -ForegroundColor Green
        Write-Host ""
        Write-Host "Stiskněte klávesu pro pokračování..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }
    
    Write-Host "CO JE MPO?" -ForegroundColor Yellow
    Write-Host "  Multi-Plane Overlay je funkce Windows DWM (Desktop Window Manager)" -ForegroundColor White
    Write-Host "  pro optimalizaci kompozice oken." -ForegroundColor White
    Write-Host ""
    Write-Host "PROBLÉMY MPO:" -ForegroundColor Red
    Write-Host "  ❌ Náhodné černé obrazovky (zejména video)" -ForegroundColor Red
    Write-Host "  ❌ Blikání obrazovky (flickering)" -ForegroundColor Red
    Write-Host "  ❌ Stuttering v prohlížečích (YouTube, Twitch)" -ForegroundColor Red
    Write-Host "  ❌ Multi-monitor nestabilita" -ForegroundColor Red
    Write-Host ""
    Write-Host "BENEFIT ZAKÁZÁNÍ:" -ForegroundColor Green
    Write-Host "  ✅ Oprava black screenů" -ForegroundColor Green
    Write-Host "  ✅ Stabilnější desktop" -ForegroundColor Green
    Write-Host "  ✅ Plynulejší video playback" -ForegroundColor Green
    Write-Host ""
    Write-Host "UNIVERZÁLNÍ:" -ForegroundColor Cyan
    Write-Host "  ✅ NVIDIA GPU" -ForegroundColor White
    Write-Host "  ✅ AMD GPU" -ForegroundColor White
    Write-Host "  ✅ Intel iGPU" -ForegroundColor White
    Write-Host ""
    Write-Host "⚠️  RESTART PC JE NUTNÝ pro aktivaci!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "──────────────────────────────────────────────────────────"
    Write-Host ""
    
    $confirm = Read-Host "Zakázat MPO? (A = Ano, N = Ne)"
    
    if ($confirm -notmatch '^[Aa]') {
        Write-Host "Operace zrušena uživatelem." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Stiskněte klávesu pro pokračování..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }
    
    Write-Host ""
    Write-Host "Aplikuji MPO tweak..." -ForegroundColor Cyan
    Write-Host ""
    
    try {
        # Použití Invoke-RegistryOperation pro bezpečnou úpravu
        $result = Invoke-RegistryOperation `
            -Path "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" `
            -Name "OverlayTestMode" `
            -Value 5 `
            -Type "DWord" `
            -CreatePath
        
        if ($result.Success) {
            Write-Host "══════════════════════════════════════════════════════════"
            Write-Host "  ✅ MPO ÚSPĚŠNĚ ZAKÁZÁNO!" -ForegroundColor Green
            Write-Host "══════════════════════════════════════════════════════════"
            Write-Host ""
            Write-Host "⚠️  RESTART PC JE NUTNÝ pro aktivaci této změny!" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "Po restartu zkontrolujte, zda problémy (black screens," -ForegroundColor Cyan
            Write-Host "flickering) zmizely." -ForegroundColor Cyan
        } else {
            Write-Warning "Selhání aplikace MPO tweaku: $($result.Error)"
        }
        
    } catch {
        Write-Error "Chyba při zakázání MPO: $($_.Exception.Message)"
    }
    
    Write-Host ""
    Write-Host "Stiskněte klávesu pro pokračování..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

<#
.SYNOPSIS
    Obnoví MPO (Multi-Plane Overlay) na výchozí stav.
    
.DESCRIPTION
    Odstraní registry klíč OverlayTestMode, čímž se MPO vrátí
    do výchozího stavu (povoleno).
#>
function Invoke-EnableMPO {
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host "  ✅ MPO (MULTI-PLANE OVERLAY) - POVOLIT"
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""
    
    $currentStatus = Get-MpoStatus
    Write-Host "Aktuální stav MPO: $currentStatus" -ForegroundColor $(if ($currentStatus -eq "Povoleno") { "Green" } else { "Yellow" })
    Write-Host ""
    
    if ($currentStatus -ne "Zakázáno") {
        Write-Host "✅ MPO je již povoleno. Není nutná žádná změna." -ForegroundColor Green
        Write-Host ""
        Write-Host "Stiskněte klávesu pro pokračování..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }
    
    Write-Host "Obnovuji MPO na výchozí stav (povoleno)..." -ForegroundColor Cyan
    Write-Host ""
    
    try {
        # Odstranění klíče = návrat k výchozímu stavu
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" -Name "OverlayTestMode" -ErrorAction Stop
        
        Write-Host "══════════════════════════════════════════════════════════"
        Write-Host "  ✅ MPO ÚSPĚŠNĚ POVOLENO!" -ForegroundColor Green
        Write-Host "══════════════════════════════════════════════════════════"
        Write-Host ""
        Write-Host "⚠️  RESTART PC JE NUTNÝ pro aktivaci této změny!" -ForegroundColor Yellow
        
    } catch {
        Write-Error "Chyba při povolení MPO: $($_.Exception.Message)"
    }
    
    Write-Host ""
    Write-Host "Stiskněte klávesu pro pokračování..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

<#
.SYNOPSIS
    Menu pro zapnutí/vypnutí MPO.
#>
function Show-MpoToggleMenu {
    Clear-Host
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host "  🚫 MPO (MULTI-PLANE OVERLAY) - TOGGLE"
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""
    
    $currentStatus = Get-MpoStatus
    Write-Host "Aktuální stav MPO: $currentStatus" -ForegroundColor $(if ($currentStatus -eq "Zakázáno") { "Green" } else { "Yellow" })
    Write-Host ""
    
    Write-Host "[1] 🚫 Zakázat MPO (Opravit black screens/flickering)" -ForegroundColor Yellow
    Write-Host "[2] ✅ Povolit MPO (Výchozí stav Windows)" -ForegroundColor Green
    Write-Host ""
    Write-Host "[Q] Zpět" -ForegroundColor Red
    Write-Host ""
    
    $choice = Read-Host "Zadejte volbu"
    
    switch ($choice.ToUpper()) {
        '1' { Invoke-DisableMPO }
        '2' { Invoke-EnableMPO }
        'Q' { return }
        default {
            Write-Warning "Neplatná volba."
            Start-Sleep 2
            Show-MpoToggleMenu
        }
    }
}

# ===========================================================
# HARDWARE GPU SCHEDULING (HAGS) TOGGLE
# ===========================================================

<#
.SYNOPSIS
    Zjistí aktuální stav HAGS.

.OUTPUTS
    String: "Zapnuto" nebo "Vypnuto"
#>
function Get-HagsStatus {
    try {
        $hags = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -ErrorAction SilentlyContinue
        if ($hags.HwSchMode -eq 2) {
            return "Zapnuto"
        } else {
            return "Vypnuto"
        }
    } catch {
        return "Neznámý"
    }
}

<#
.SYNOPSIS
    Menu pro zapnutí/vypnutí HAGS.
#>
function Show-HagsToggleMenu {
    Clear-Host
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host "  ⚡ HARDWARE GPU SCHEDULING (HAGS) - TOGGLE"
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""
    
    $currentStatus = Get-HagsStatus
    Write-Host "Aktuální stav: $currentStatus" -ForegroundColor $(if ($currentStatus -eq "Zapnuto") { "Green" } else { "Yellow" })
    Write-Host ""
    
    Write-Host "CO JE HAGS?" -ForegroundColor Yellow
    Write-Host "  Hardware-Accelerated GPU Scheduling umožňuje GPU" -ForegroundColor White
    Write-Host "  spravovat své vlastní úlohy místo CPU." -ForegroundColor White
    Write-Host ""
    Write-Host "VÝHODY:" -ForegroundColor Green
    Write-Host "  ✅ Input lag -1-3ms" -ForegroundColor Green
    Write-Host "  ✅ Plynulejší frame pacing" -ForegroundColor Green
    Write-Host "  ✅ Lepší multi-tasking" -ForegroundColor Green
    Write-Host ""
    Write-Host "KOMPATIBILITA:" -ForegroundColor Yellow
    Write-Host "  ✅ NVIDIA RTX 20xx/30xx/40xx (doporučeno)" -ForegroundColor Green
    Write-Host "  ⚠️ AMD RX 6xxx/7xxx (testovat individuálně)" -ForegroundColor Yellow
    Write-Host "  ⚠️ Intel Xe (minimální benefit)" -ForegroundColor Yellow
    Write-Host "  ❌ Starší GPU (GTX 10xx, RX 5xxx) - nedoporučeno" -ForegroundColor Red
    Write-Host ""
    Write-Host "⚠️  VAROVÁNÍ:" -ForegroundColor Yellow
    Write-Host "  • Vyžaduje RESTART PC" -ForegroundColor White
    Write-Host "  • AMD: Smíšené výsledky (testovat!)" -ForegroundColor White
    Write-Host "  • Starší hardware: Možné problémy" -ForegroundColor White
    Write-Host ""
    
    Write-Host "──────────────────────────────────────────────────────────"
    Write-Host "[1] ✅ Zapnout HAGS (HwSchMode = 2)" -ForegroundColor Green
    Write-Host "[2] ❌ Vypnout HAGS (HwSchMode = 1)" -ForegroundColor Red
    Write-Host "[Q] ⬅️  Zpět" -ForegroundColor Yellow
    Write-Host ""
    
    $choice = Read-Host -Prompt "Zadejte svou volbu"
    
    switch ($choice.ToUpper()) {
        '1' { 
            Write-Host ""
            Write-Host "Zapínám Hardware GPU Scheduling..." -ForegroundColor Cyan
            
            try {
                # Použití Invoke-RegistryOperation pro správné oprávnění
                $result = Invoke-RegistryOperation `
                    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" `
                    -Name "HwSchMode" `
                    -Value 2 `
                    -Type "DWord"
                
                if ($result.Success) {
                    Write-Host ""
                    Write-Host "✅ HAGS byl ZAPNUT!" -ForegroundColor Green
                    Write-Host "   HwSchMode = 2" -ForegroundColor Green
                    Write-Host ""
                    Write-Host "⚠️  RESTART PC JE NUTNÝ pro aktivaci!" -ForegroundColor Yellow
                    Write-Host ""
                    Write-Host "💡 TIP: Po restartu testujte benefit ve vašich hrách." -ForegroundColor Cyan
                } else {
                    Write-Warning "Chyba při zapínání HAGS: $($result.Error)"
                }
            } catch {
                Write-Error "Kritická chyba: $($_.Exception.Message)"
            }
            
            Write-Host ""
            Write-Host "Stiskněte klávesu pro pokračování..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        '2' { 
            Write-Host ""
            Write-Host "Vypínám Hardware GPU Scheduling..." -ForegroundColor Cyan
            
            try {
                $result = Invoke-RegistryOperation `
                    -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" `
                    -Name "HwSchMode" `
                    -Value 1 `
                    -Type "DWord"
                
                if ($result.Success) {
                    Write-Host ""
                    Write-Host "✅ HAGS byl VYPNUT!" -ForegroundColor Green
                    Write-Host "   HwSchMode = 1" -ForegroundColor Green
                    Write-Host ""
                    Write-Host "⚠️  RESTART PC JE NUTNÝ pro deaktivaci!" -ForegroundColor Yellow
                } else {
                    Write-Warning "Chyba při vypínání HAGS: $($result.Error)"
                }
            } catch {
                Write-Error "Kritická chyba: $($_.Exception.Message)"
            }
            
            Write-Host ""
            Write-Host "Stiskněte klávesu pro pokračování..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        'Q' { return }
        default {
            Write-Warning "Neplatná volba."
            Start-Sleep 2
        }
    }
}

# ===========================================================
# WINDOWS HERNÍ REŽIM TOGGLE
# ===========================================================

<#
.SYNOPSIS
    Zjistí aktuální stav Windows Herního režimu.

.OUTPUTS
    String: "Zapnuto" nebo "Vypnuto"
#>
function Get-GameModeStatus {
    try {
        $gameMode = Get-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -ErrorAction SilentlyContinue
        if ($gameMode.AllowAutoGameMode -eq 1) {
            return "Zapnuto"
        } else {
            return "Vypnuto"
        }
    } catch {
        return "Neznámý"
    }
}

<#
.SYNOPSIS
    Menu pro zapnutí/vypnutí Windows Herního režimu.
#>
function Show-GameModeToggleMenu {
    Clear-Host
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host "  🎮 WINDOWS HERNÍ REŽIM - TOGGLE"
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""
    
    $currentStatus = Get-GameModeStatus
    Write-Host "Aktuální stav: $currentStatus" -ForegroundColor $(if ($currentStatus -eq "Zapnuto") { "Green" } else { "Yellow" })
    Write-Host ""
    
    Write-Host "CO JE HERNÍ REŽIM?" -ForegroundColor Yellow
    Write-Host "  Windows Herní režim optimalizuje systém pro hry:" -ForegroundColor White
    Write-Host "  • Prioritizuje hru (vyšší CPU priorita)" -ForegroundColor White
    Write-Host "  • Vypíná Windows Update na pozadí" -ForegroundColor White
    Write-Host "  • Redukuje notifikace a popupy" -ForegroundColor White
    Write-Host "  • Snižuje zátěž od background procesů" -ForegroundColor White
    Write-Host ""
    Write-Host "VÝHODY:" -ForegroundColor Green
    Write-Host "  ✅ Stabilnější FPS (méně dropů)" -ForegroundColor Green
    Write-Host "  ✅ Prioritizace hry před jinými procesy" -ForegroundColor Green
    Write-Host "  ✅ Žádné Windows Update interrupts" -ForegroundColor Green
    Write-Host ""
    Write-Host "NEVÝHODY:" -ForegroundColor Yellow
    Write-Host "  ⚠️ Background aplikace mají nižší prioritu" -ForegroundColor Yellow
    Write-Host "  ⚠️ Discord/Streaming může být ovlivněn" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "DOPORUČENÍ:" -ForegroundColor Cyan
    Write-Host "  ✅ Zapnout pro gaming sessions" -ForegroundColor Green
    Write-Host "  ❌ Vypnout pokud streamujete/nahrávat" -ForegroundColor Red
    Write-Host ""
    
    Write-Host "──────────────────────────────────────────────────────────"
    Write-Host "[1] ✅ Zapnout Herní režim" -ForegroundColor Green
    Write-Host "[2] ❌ Vypnout Herní režim" -ForegroundColor Red
    Write-Host "[Q] ⬅️  Zpět" -ForegroundColor Yellow
    Write-Host ""
    
    $choice = Read-Host -Prompt "Zadejte svou volbu"
    
    switch ($choice.ToUpper()) {
        '1' { 
            Write-Host ""
            Write-Host "Zapínám Windows Herní režim..." -ForegroundColor Cyan
            
            try {
                # HKCU cesta (user-specific)
                if (-not (Test-Path "HKCU:\Software\Microsoft\GameBar")) {
                    New-Item -Path "HKCU:\Software\Microsoft\GameBar" -Force | Out-Null
                }
                
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 1 -Type DWord -Force
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                
                Write-Host ""
                Write-Host "✅ HERNÍ REŽIM byl ZAPNUT!" -ForegroundColor Green
                Write-Host "   AllowAutoGameMode = 1" -ForegroundColor Green
                Write-Host ""
                Write-Host "💡 Herní režim se aktivuje automaticky při spuštění hry." -ForegroundColor Cyan
                Write-Host "   (Game Bar musí detekovat fullscreen aplikaci)" -ForegroundColor Gray
            } catch {
                Write-Error "Chyba při zapínání Herního režimu: $($_.Exception.Message)"
            }
            
            Write-Host ""
            Write-Host "Stiskněte klávesu pro pokračování..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        '2' { 
            Write-Host ""
            Write-Host "Vypínám Windows Herní režim..." -ForegroundColor Cyan
            
            try {
                if (-not (Test-Path "HKCU:\Software\Microsoft\GameBar")) {
                    New-Item -Path "HKCU:\Software\Microsoft\GameBar" -Force | Out-Null
                }
                
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AllowAutoGameMode" -Value 0 -Type DWord -Force
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "AutoGameModeEnabled" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                
                Write-Host ""
                Write-Host "✅ HERNÍ REŽIM byl VYPNUT!" -ForegroundColor Green
                Write-Host "   AllowAutoGameMode = 0" -ForegroundColor Green
            } catch {
                Write-Error "Chyba při vypínání Herního režimu: $($_.Exception.Message)"
            }
            
            Write-Host ""
            Write-Host "Stiskněte klávesu pro pokračování..."
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        }
        'Q' { return }
        default {
            Write-Warning "Neplatná volba."
            Start-Sleep 2
        }
    }
}

# ===========================================================
# RESIZABLE BAR INFO & CHECK
# ===========================================================

<#
.SYNOPSIS
    Zobrazí informace o Resizable BAR a zkontroluje stav.
#>
function Show-ResizableBarInfo {
    Clear-Host
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host "  📊 RESIZABLE BAR (SAM) - INFO & CHECK"
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""
    
    Write-Host "CO JE RESIZABLE BAR?" -ForegroundColor Yellow
    Write-Host "  PCIe standard, který umožňuje CPU přistupovat k CELÉ" -ForegroundColor White
    Write-Host "  VRAM GPU najednou (místo 256MB chunks)." -ForegroundColor White
    Write-Host ""
    Write-Host "  BEZ ReBAR: CPU vidí jen 256MB chunks VRAM" -ForegroundColor Gray
    Write-Host "  S ReBAR:   CPU vidí CELOU VRAM (8GB/16GB/24GB)" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "PODPOROVANÉ GPU:" -ForegroundColor Yellow
    Write-Host "  ✅ NVIDIA RTX 30xx, 40xx (driver 465.89+)" -ForegroundColor Green
    Write-Host "  ✅ AMD RX 6xxx, 7xxx (RDNA2/3)" -ForegroundColor Green
    Write-Host "  ✅ Intel Arc Axxx (KRITICKÉ! +40% FPS)" -ForegroundColor Green
    Write-Host "  ⚠️ NVIDIA RTX 20xx (experimentální, driver 496.76+)" -ForegroundColor Yellow
    Write-Host "  ❌ NVIDIA GTX 10xx a starší" -ForegroundColor Red
    Write-Host "  ❌ AMD RX 5xxx a starší" -ForegroundColor Red
    Write-Host ""
    
    Write-Host "BENEFIT:" -ForegroundColor Cyan
    Write-Host "  • NVIDIA RTX 30xx/40xx: +3-8% FPS" -ForegroundColor White
    Write-Host "  • AMD RX 6xxx/7xxx: +10-16% FPS (SAM)" -ForegroundColor White
    Write-Host "  • Intel Arc: +20-40% FPS (KRITICKÉ!)" -ForegroundColor White
    Write-Host ""
    
    Write-Host "POŽADAVKY:" -ForegroundColor Yellow
    Write-Host "  ✅ Moderní CPU (Intel 10th gen+ / AMD Zen 3+)" -ForegroundColor White
    Write-Host "  ✅ Moderní motherboard (2020+)" -ForegroundColor White
    Write-Host "  ✅ BIOS: 'Resizable BAR' nebo 'SAM' = Enabled" -ForegroundColor White
    Write-Host ""
    
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host "  KONTROLA RESIZABLE BAR" -ForegroundColor Cyan
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""
    
    # Zjistit GPU
    try {
        $gpu = Get-WmiObject Win32_VideoController -ErrorAction Stop | Select-Object -First 1
        Write-Host "GPU: $($gpu.Name)" -ForegroundColor Cyan
        Write-Host "VRAM: $([math]::Round($gpu.AdapterRAM / 1GB, 2)) GB" -ForegroundColor Cyan
        Write-Host ""
        
        # Heuristická kontrola ReBAR (není 100% přesná, ale indikuje)
        if ($gpu.AdapterRAM -gt 268435456) {
            Write-Host "⚠️  ReBAR pravděpodobně: ZAPNUT" -ForegroundColor Green
            Write-Host "   (AdapterRAM > 256MB viditelný v systému)" -ForegroundColor Gray
        } else {
            Write-Host "⚠️  ReBAR pravděpodobně: VYPNUT" -ForegroundColor Yellow
            Write-Host "   (AdapterRAM = 256MB limit)" -ForegroundColor Gray
        }
        
        Write-Host ""
        Write-Host "💡 Pro přesné ověření použij: GPU-Z → Advanced → 'Resizable BAR'" -ForegroundColor Cyan
        Write-Host "   Download: https://www.techpowerup.com/gpuz/" -ForegroundColor Gray
        
    } catch {
        Write-Warning "Nepodařilo se získat informace o GPU."
    }
    
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host "  JAK ZAPNOUT RESIZABLE BAR" -ForegroundColor Yellow
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""
    Write-Host "1. Update BIOS na nejnovější verzi" -ForegroundColor White
    Write-Host "2. Vstup do BIOS (DEL nebo F2 při bootování)" -ForegroundColor White
    Write-Host "3. Najdi nastavení:" -ForegroundColor White
    Write-Host "   • 'Resizable BAR' (NVIDIA/Intel)" -ForegroundColor Gray
    Write-Host "   • 'Smart Access Memory' (AMD)" -ForegroundColor Gray
    Write-Host "   • 'Above 4G Decoding' = Enabled (prerekvizita)" -ForegroundColor Gray
    Write-Host "4. Zapni Resizable BAR = Enabled" -ForegroundColor White
    Write-Host "5. Ulož a restart" -ForegroundColor White
    Write-Host "6. Ověř v GPU-Z" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Stiskněte klávesu pro návrat..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ===========================================================
# ADVANCED GPU INFO
# ===========================================================

<#
.SYNOPSIS
    Zobrazí detailní info o všech pokročilých GPU funkcích.
#>
function Show-AdvancedGpuInfo {
    Clear-Host
    Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "      ℹ️  POKROČILÉ GPU FUNKCE - DOKUMENTACE" -ForegroundColor White
    Write-Host "══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "═══ HARDWARE GPU SCHEDULING (HAGS) ═══" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Registry:" -ForegroundColor Cyan
    Write-Host "  HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -ForegroundColor Gray
    Write-Host "  HwSchMode = 1 (OFF) / 2 (ON)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Kompatibilita:" -ForegroundColor Cyan
    Write-Host "  ✅ NVIDIA RTX 20xx+ (doporučeno)" -ForegroundColor Green
    Write-Host "  ⚠️ AMD RX 6xxx+ (testovat!)" -ForegroundColor Yellow
    Write-Host "  ⚠️ Intel Xe (minimální benefit)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Benefit: Input lag -1-3ms, lepší frame pacing" -ForegroundColor White
    Write-Host "Restart: ✅ Vyžadován" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Host "═══ WINDOWS HERNÍ REŽIM ═══" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Registry:" -ForegroundColor Cyan
    Write-Host "  HKCU:\Software\Microsoft\GameBar" -ForegroundColor Gray
    Write-Host "  AllowAutoGameMode = 0 (OFF) / 1 (ON)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Funkce:" -ForegroundColor Cyan
    Write-Host "  • Prioritizuje hru (CPU priorita)" -ForegroundColor White
    Write-Host "  • Vypíná Windows Update na pozadí" -ForegroundColor White
    Write-Host "  • Redukuje notifikace" -ForegroundColor White
    Write-Host ""
    Write-Host "Benefit: Stabilnější FPS, méně interrupts" -ForegroundColor White
    Write-Host "Restart: ❌ Není nutný" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "═══ RESIZABLE BAR (SAM) ═══" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Benefit:" -ForegroundColor Cyan
    Write-Host "  • NVIDIA RTX 30xx/40xx: +3-8% FPS" -ForegroundColor White
    Write-Host "  • AMD RX 6xxx/7xxx: +10-16% FPS" -ForegroundColor White
    Write-Host "  • Intel Arc: +20-40% FPS (KRITICKÉ!)" -ForegroundColor White
    Write-Host ""
    Write-Host "Nastavení: V BIOS (ne v Windows)" -ForegroundColor White
    Write-Host "Ověření: GPU-Z → Advanced tab" -ForegroundColor White
    Write-Host ""
    
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""
    Write-Host "📄 DETAILNÍ DOKUMENTACE:" -ForegroundColor Yellow
    Write-Host ""
    
    $docHags = Join-Path (Split-Path $PSScriptRoot -Parent) "GPU-HAGS-DOCUMENTATION.md"
    if (Test-Path $docHags) {
        Write-Host "  ✅ GPU-HAGS-DOCUMENTATION.md" -ForegroundColor Green
        Write-Host "     Cesta: $docHags" -ForegroundColor Gray
        Write-Host "     Obsah: Kompletní HAGS dokumentace (235 řádků)" -ForegroundColor Gray
    } else {
        Write-Host "  ⚠️ GPU-HAGS-DOCUMENTATION.md - NENALEZENO" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "══════════════════════════════════════════════════════════"
    Write-Host ""
    Write-Host "Stiskněte klávesu pro návrat..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ===========================================================
# MODULE EXPORTS
# ===========================================================

function Invoke-ModuleEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $ModuleContext
    )

    if ($null -eq $ModuleContext) {
        throw [System.ArgumentNullException]::new('ModuleContext')
    }

    Show-AdvancedGpuMenu
}

Export-ModuleMember -Function @(
    # Main menu
    'Show-AdvancedGpuMenu',
    
    # Status check functions
    'Get-HagsStatus',
    'Get-GameModeStatus',
    'Get-MpoStatus',
    
    # MPO functions
    'Invoke-DisableMPO',
    'Invoke-EnableMPO',
    'Show-MpoToggleMenu',
    'Invoke-ModuleEntry'
)

# ===========================================================
# MODULE INITIALIZATION LOG
# ===========================================================

if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
    Write-CoreLog -Message "GPU_Advanced.psm1 v$script:ModuleVersion loaded successfully" -Level Info
}

