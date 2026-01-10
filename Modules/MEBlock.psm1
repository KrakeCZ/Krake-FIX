# ═══════════════════════════════════════════════════════════════════════════
# Module: MEBlock.psm1 - Microsoft Edge Blockade 
# ═══════════════════════════════════════════════════════════════════════════
# Project:      KRAKE-FIX 
# ═══════════════════════════════════════════════════════════════════════════
# Description:  Microsoft Edge blockade (Registry/IFEO/ACL) 
#               3 varianty: Light, Medium, Hardcore (8-layer ACL lock)
# Category:     System Tweaks / Security
# Dependencies: Core.psm1 (Invoke-AsSystem, Invoke-AsTrustedInstaller)
# Admin Rights: REQUIRED (Registry HKLM, IFEO, ACL, Firewall, Services)
# ═══════════════════════════════════════════════════════════════════════════
# ⚠️  SECURITY & COMPLIANCE NOTICE
# ═══════════════════════════════════════════════════════════════════════════
# • This module implements Edge blockade (Registry, IFEO, ACL, Firewall)
# • Designed for educational and testing purposes only
# • Hardcore variant uses ACL DENY for SYSTEM/TrustedInstaller
# • Author assumes no liability for misuse outside academic context
# ===========================================================
# ⚠️ Tento modul může měnit systémové nastavení.
# Používej pouze ve studijním / testovacím prostředí.
# Autor neručí za zneužití mimo akademické účely.
# ═══════════════════════════════════════════════════════════════════════════
#Requires -Version 5.1
#Requires -RunAsAdministrator
using namespace System.Management.Automation
# ───────────────────────────────────────────────────────────────────────────
# MODULE INITIALIZATION
# ───────────────────────────────────────────────────────────────────────────
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Module-level variables (private)
$script:ModuleName = 'MEBlock'
$script:ModuleVersion = '2.0.0'
# ═══════════════════════════════════════════════════════════════════════════
# CRITICAL DEPENDENCY: Core.psm1 (with fail-fast validation)
# ═══════════════════════════════════════════════════════════════════════════
# Use Core module functions - loaded by Main.ps1, only import if standalone
if (-not (Get-Command Write-CoreLog -ErrorAction SilentlyContinue)) {
    $corePath = Join-Path -Path $PSScriptRoot -ChildPath 'Core.psm1'
    if (-not (Test-Path $corePath)) {
        Write-Error "CRITICAL: Core.psm1 not found at: $corePath"
        Write-Error "MEBlock.psm1 requires Core.psm1 for privilege management."
        throw "Missing dependency: Core.psm1"
    }
    try {
        Import-Module $corePath -Force -Global -ErrorAction Stop
        # Validate that critical functions are available
        $requiredFunctions = @(
            'Invoke-RegistryOperation',
            'Invoke-WithPrivilege',
            'Write-CoreLog'
        )
        $missingFunctions = @($requiredFunctions | Where-Object {
                -not (Get-Command $_ -ErrorAction SilentlyContinue)
            })
        if ($missingFunctions.Count -gt 0) {
            Write-Error "CRITICAL: Core.psm1 loaded but missing required functions: $($missingFunctions -join ', ')"
            throw "Core.psm1 incomplete: Missing $($missingFunctions.Count) function(s)"
        }
        # Log successful import
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "MEBlock.psm1: Core.psm1 imported successfully with all required functions" -Level Info
        }
    }
    catch {
        Write-Error "CRITICAL: Failed to import Core.psm1: $($_.Exception.Message)"
        Write-Error "MEBlock.psm1 cannot continue without Core.psm1"
        throw
    }
}
# ═══════════════════════════════════════════════════════════════════════════
# PUBLIC FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════
<#
.SYNOPSIS
    Interactive menu for Microsoft Edge blockade.
.DESCRIPTION
    Displays menu with 3 blockade variants:
    - [A] LIGHT: Registry + Services
    - [B] MEDIUM: + IFEO + Firewall
    - [C] HARDCORE: + ACL Lock (8 layers, DENY for SYSTEM/TI)
    - [U] UNLOCK: Remove blockade (standard)
    - [R] ACL UNLOCK: Remove ACL lock (via SYSTEM Task Scheduler)
.NOTES
    Based on KRAKE-FIX-v1.ps1 function Invoke-EdgeBlockadeMenu
    Per @STUDY/02-Registry-Security-Deep-Dive.md
#>
function Show-EdgeBlockadeMenu {
    [CmdletBinding()]
    param()
    while ($true) {
        Clear-Host
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
        Write-Host "  🗑️  MICROSOFT EDGE BLOCKADE - VÝBĚR VARIANTY" -ForegroundColor Magenta
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Vyberte úroveň blokace Microsoft Edge:" -ForegroundColor White
        Write-Host ""
        Write-Host "[A] 📝 LEHKÁ - Registry + Služby" -ForegroundColor Green
        Write-Host "    → Zakáže Edge politiky, služby EdgeUpdate, plánované úlohy" -ForegroundColor Gray
        Write-Host "    → Bezpečné, snadno reverzibilní" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[B] ⚙️  STŘEDNÍ - + IFEO + Firewall" -ForegroundColor Yellow
        Write-Host "    → Varianta A + IFEO Kill-Switch + DisallowRun" -ForegroundColor Gray
        Write-Host "    → Firewall blokace msedge.exe" -ForegroundColor Gray
        Write-Host "    → Silnější blokace, stále reverzibilní" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[C] 🔒 HARDCORE - + ACL Lock (8 vrstev)" -ForegroundColor Red
        Write-Host "    → Varianta B + ACL zámek IFEO klíčů" -ForegroundColor Gray
        Write-Host "    → Telemetrie, Widgets, Web Search blokace" -ForegroundColor Gray
        Write-Host "    → DENY pro SYSTEM/TrustedInstaller" -ForegroundColor Gray
        Write-Host "    ⚠️  JEDNORÁZOVÉ! Bez watchdogů/cyklických úloh!" -ForegroundColor Yellow
        Write-Host "    ⚠️  VAROVÁNÍ: Revert vyžaduje speciální postup!" -ForegroundColor Red
        Write-Host ""
        Write-Host "[U] 🔓 UNLOCK/REVERT - Odstranit blokaci" -ForegroundColor Cyan
        Write-Host "    → Odstraní IFEO, DisallowRun, Firewall" -ForegroundColor Gray
        Write-Host "    → Pro ACL Lock nutno použít speciální unlock!" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[R] 🔐 ACL UNLOCK - Odemknout ACL zámek (pro Variantu C)" -ForegroundColor Magenta
        Write-Host "    → Odstraní DENY na IFEO klíčích" -ForegroundColor Gray
        Write-Host "    → Spustí jako SYSTEM přes Task Scheduler" -ForegroundColor Gray
        Write-Host ""
        Write-Host "───────────────────────────────────────────────────────────────"
        Write-Host "[I] ℹ️  INFO - Jak to funguje? Proč bez watchdogů?" -ForegroundColor White
        Write-Host "    → Edukace: Statická blokace vs Watchdog" -ForegroundColor Gray
        Write-Host "    → Gaming-friendly design" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[Q] ⬅️  Zpět do hlavního menu" -ForegroundColor Red
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""
        $choice = Read-Host -Prompt "Zadejte svou volbu"
        switch ($choice.ToUpper()) {
            'A' { Invoke-EdgeBlockade -Variant 'Light' }
            'B' { Invoke-EdgeBlockade -Variant 'Medium' }
            'C' { Invoke-EdgeBlockade -Variant 'Hardcore' }
            'U' { Invoke-EdgeUnlock -Mode 'Standard' }
            'R' { Invoke-EdgeUnlock -Mode 'ACL' }
            'I' { Show-EdgeBlockadeInfo }
            'Q' { return }
            default {
                Write-Warning "Neplatná volba. Zkuste to znovu."
                Start-Sleep -Seconds 2
            }
        }
    }
}
<#
.SYNOPSIS
    Zobrazí edukační informace o Edge blokaci a watchdogech.
.DESCRIPTION
    Vysvětluje:
    - Co je statická blokace
    - Co jsou watchdogs
    - Proč watchdogs nepoužíváme
    - Výhody/nevýhody obou přístupů
    - Gaming-friendly design
.NOTES
    Educational content for users
#>
function Show-EdgeBlockadeInfo {
    [CmdletBinding()]
    param()
    Clear-Host
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "    ℹ️  EDGE BLOCKADE - JAK TO FUNGUJE?" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "═══ 🔒 STATICKÁ BLOKACE (náš přístup) ═══" -ForegroundColor Green
    Write-Host ""
    Write-Host "Co to je:" -ForegroundColor Yellow
    Write-Host "  Jednorázové nastavení systému, které NEBĚŽÍ na pozadí." -ForegroundColor White
    Write-Host ""
    Write-Host "Jak to funguje:" -ForegroundColor Yellow
    Write-Host "  1. Spustíš skript JEDNOU" -ForegroundColor White
    Write-Host "  2. Aplikuje 8 vrstev blokace (Registry, IFEO, Firewall...)" -ForegroundColor White
    Write-Host "  3. Restart PC" -ForegroundColor White
    Write-Host "  4. Edge je ZABLOKOVÁN" -ForegroundColor White
    Write-Host "  5. Skript končí - ŽÁDNÝ proces na pozadí!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Výhody:" -ForegroundColor Yellow
    Write-Host "  ✅ 0% CPU overhead" -ForegroundColor Green
    Write-Host "  ✅ 0 MB RAM overhead" -ForegroundColor Green
    Write-Host "  ✅ 0 I/O operací na pozadí" -ForegroundColor Green
    Write-Host "  ✅ 0 možností micro-stutterů" -ForegroundColor Green
    Write-Host "  ✅ 100% gaming performance" -ForegroundColor Green
    Write-Host ""
    Write-Host "Nevýhody:" -ForegroundColor Yellow
    Write-Host "  ⚠️  Pokud Windows Update něco změní, musíš skript spustit znovu" -ForegroundColor Yellow
    Write-Host "  ⚠️  Není automatická oprava (to je cena za 0% overhead!)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "═══ 🐕 WATCHDOG (co to je a proč ho NEPOUŽÍVÁME) ═══" -ForegroundColor Red
    Write-Host ""
    Write-Host "Co to je:" -ForegroundColor Yellow
    Write-Host "  'Hlídací pes' = Proces běžící 24/7 na pozadí," -ForegroundColor White
    Write-Host "  který PERIODICKY kontroluje systém a automaticky opravuje změny." -ForegroundColor White
    Write-Host ""
    Write-Host "Jak by fungoval (kdyby ho používali):" -ForegroundColor Yellow
    Write-Host "  1. Watchdog běží POŘÁD na pozadí" -ForegroundColor White
    Write-Host "  2. Každou minutu zkontroluje IFEO klíče" -ForegroundColor White
    Write-Host "  3. Pokud někdo odstranil blokaci → AUTOMATICKY OPRAVÍ" -ForegroundColor White
    Write-Host "  4. Běží 24/7, i když hraješ!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Proč ho NEPOUŽÍVÁME:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  ❌ VÝKONNOSTNÍ OVERHEAD:" -ForegroundColor Red
    Write-Host "     • Zabírá RAM: 50-100 MB" -ForegroundColor White
    Write-Host "     • Zabírá CPU: 0.1-0.5% (i když jen trochu)" -ForegroundColor White
    Write-Host "     • I/O operace každou minutu → износ SSD" -ForegroundColor White
    Write-Host "     • Context switching → možné micro-stuttery!" -ForegroundColor White
    Write-Host ""
    Write-Host "  ❌ NEPŘEDVÍDATELNOST:" -ForegroundColor Red
    Write-Host "     • Plánovač úloh může watchdog spustit KDYKOLIV" -ForegroundColor White
    Write-Host "     • Během důležitého souboje ve hře" -ForegroundColor White
    Write-Host "     • Během loadingu" -ForegroundColor White
    Write-Host "     • → Výsledek: LAG, STUTTER, FPS DROP!" -ForegroundColor White
    Write-Host ""
    Write-Host "  ❌ BATTERY/THERMAL:" -ForegroundColor Red
    Write-Host "     • Vyšší teploty (i když minimálně)" -ForegroundColor White
    Write-Host "     • Kratší životnost baterie (laptopy)" -ForegroundColor White
    Write-Host "     • Zbytečná zátěž" -ForegroundColor White
    Write-Host ""
    Write-Host "  ❌ GAMING = ZERO TOLERANCE:" -ForegroundColor Red
    Write-Host "     • Pro esports/competitive gaming:" -ForegroundColor White
    Write-Host "       → ŽÁDNÉ procesy na pozadí" -ForegroundColor White
    Write-Host "       → ŽÁDNÉ periodické kontroly" -ForegroundColor White
    Write-Host "       → Jen statická konfigurace + restart!" -ForegroundColor White
    Write-Host ""
    Write-Host "═══ 📊 POROVNÁNÍ ═══" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "┌─────────────────────┬──────────────┬───────────────────┐" -ForegroundColor Gray
    Write-Host "│ Aspekt              │ WATCHDOG ❌  │ STATICKÁ BLOKACE ✅│" -ForegroundColor Gray
    Write-Host "├─────────────────────┼──────────────┼───────────────────┤" -ForegroundColor Gray
    Write-Host "│ Běží na pozadí      │ Ano (POŘÁD)  │ Ne (jen install)  │" -ForegroundColor White
    Write-Host "│ CPU overhead        │ 0.1-0.5%     │ 0%                │" -ForegroundColor White
    Write-Host "│ RAM overhead        │ 50-100 MB    │ 0 MB              │" -ForegroundColor White
    Write-Host "│ I/O operace         │ Každou min   │ Žádné             │" -ForegroundColor White
    Write-Host "│ Micro-stuttery      │ Možné        │ Nemožné           │" -ForegroundColor White
    Write-Host "│ Gaming vhodné       │ NE ❌        │ ANO ✅            │" -ForegroundColor White
    Write-Host "│ Auto-oprava         │ Ano          │ Ne (manuál)       │" -ForegroundColor White
    Write-Host "└─────────────────────┴──────────────┴───────────────────┘" -ForegroundColor Gray
    Write-Host ""
    Write-Host "═══ 🎯 ZÁVĚR ═══" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "KRAKE-FIX používá STATICKOU BLOKACI = GAMING-FRIENDLY!" -ForegroundColor Green
    Write-Host ""
    Write-Host "✅ Žádné watchdogy" -ForegroundColor Green
    Write-Host "✅ Žádné procesy na pozadí" -ForegroundColor Green
    Write-Host "✅ Žádný výkonnostní overhead" -ForegroundColor Green
    Write-Host "✅ 100% performance pro hry" -ForegroundColor Green
    Write-Host ""
    Write-Host "⚠️  Cena: Pokud Windows Update změní nastavení," -ForegroundColor Yellow
    Write-Host "    musíš skript spustit znovu. Ale to je VÝJIMEČNÉ!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Stiskněte klávesu pro návrat do menu..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
<#
.SYNOPSIS
    Implements Microsoft Edge blockade with 3 variants.
.DESCRIPTION
    Blockade variants:
    - Light: Registry policies + Services + Scheduled Tasks
    - Medium: + IFEO Kill-Switch + DisallowRun + Firewall
    - Hardcore: + ACL Lock (DENY for SYSTEM/TrustedInstaller)
.PARAMETER Variant
    Blockade level: 'Light', 'Medium', or 'Hardcore'
.EXAMPLE
    Invoke-EdgeBlockade -Variant 'Medium'
.NOTES
#>
function Invoke-EdgeBlockade {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Light', 'Medium', 'Hardcore')]
        [string]$Variant
    )
    Clear-Host
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  MICROSOFT EDGE BLOCKADE - VARIANTA: $Variant" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    # Audit log: Blockade start
    if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
        Write-CoreLog -Message "Edge Blockade initiated: Variant=$Variant, User=$env:USERNAME, Computer=$env:COMPUTERNAME" -Level Warning
    }
    try {
        # --- VRSTVA 1: Edge Policies (Všechny varianty) ---
        Write-Host "[1/?) Aplikuji Edge Debloat politiky..." -ForegroundColor Yellow
        $edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
        $edgePolicies = @{
            PersonalizationReportingEnabled = 0; ShowRecommendationsEnabled = 0; HideFirstRunExperience = 1;
            UserFeedbackAllowed = 0; ConfigureDoNotTrack = 1; AlternateErrorPagesEnabled = 0;
            EdgeCollectionsEnabled = 0; EdgeShoppingAssistantEnabled = 0; MicrosoftEdgeInsiderPromotionEnabled = 0;
            ShowMicrosoftRewards = 0; WebWidgetAllowed = 0; DiagnosticData = 0;
            EdgeAssetDeliveryServiceEnabled = 0; CryptoWalletEnabled = 0; WalletDonationEnabled = 0;
            BackgroundModeEnabled = 0; StartupBoostEnabled = 0
        }
        $successCount = 0
        foreach ($key in $edgePolicies.Keys) {
            $result = Invoke-RegistryOperation `
                -Path $edgePolicyPath `
                -Name $key `
                -Value $edgePolicies[$key] `
                -Type "DWord" `
                -CreatePath
            if ($result.Success) {
                $successCount++
            }
            else {
                Write-Warning "Failed to set ${key}: $($result.Error)"
            }
        }
        Write-Host "  ✅ Edge politiky aplikovány ($successCount/$($edgePolicies.Count))" -ForegroundColor Green
        # --- VRSTVA 2: EdgeUpdate Politiky (Všechny varianty) ---
        Write-Host "[2/?) Zakazuji Edge Update..." -ForegroundColor Yellow
        $edgeUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"
        $result1 = Invoke-RegistryOperation `
            -Path $edgeUpdatePath `
            -Name "UpdateDefault" `
            -Value 0 `
            -Type "DWord" `
            -CreatePath
        $result2 = Invoke-RegistryOperation `
            -Path $edgeUpdatePath `
            -Name "InstallDefault" `
            -Value 0 `
            -Type "DWord" `
            -CreatePath
        if ($result1.Success -and $result2.Success) {
            Write-Host "  ✅ Edge Update zakázán (2/2)" -ForegroundColor Green
        }
        else {
            Write-Warning "Edge Update políčka částečně selhaly."
        }
        # --- VRSTVA 3: Služby EdgeUpdate (Všechny varianty) ---
        Write-Host "[3/?) Zastavuji a zakazuji služby EdgeUpdate..." -ForegroundColor Yellow
        foreach ($svcName in 'edgeupdate', 'edgeupdatem') {
            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if ($null -ne $svc) {
                Stop-Service -InputObject $svc -Force -ErrorAction SilentlyContinue
                Set-Service -InputObject $svc -StartupType Disabled -ErrorAction SilentlyContinue
                Write-Host "  ✅ Služba '$svcName' zakázána" -ForegroundColor Green
            }
        }
        # --- VRSTVA 4: Plánované úlohy EdgeUpdate (Všechny varianty) ---
        Write-Host "[4/?) Zakazuji plánované úlohy EdgeUpdate..." -ForegroundColor Yellow
        $edgeTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.TaskName -like '*Edge*' })
        if ($edgeTasks.Count -gt 0) {
            $edgeTasks | Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
            Write-Host "  ✅ Plánované úlohy Edge zakázány ($($edgeTasks.Count) úloh)" -ForegroundColor Green
        }
        # --- Pro VARIANTU MEDIUM a HARDCORE: DisallowRun ---
        if ($Variant -eq 'Medium' -or $Variant -eq 'Hardcore') {
            Write-Host "[5/?) Aplikuji DisallowRun politiku..." -ForegroundColor Yellow
            $drHKLM = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"
            $drHKCU = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun"
            # HKLM - vyžaduje Invoke-RegistryOperation
            $resultHKLM = Invoke-RegistryOperation `
                -Path $drHKLM `
                -Name "1" `
                -Value "msedge.exe" `
                -Type "String" `
                -CreatePath
            # HKCU - přímý přístup je OK (user-specific)
            if (-not (Test-Path $drHKCU)) {
                New-Item -Path $drHKCU -Force -ErrorAction Stop | Out-Null
            }
            Set-ItemProperty -Path $drHKCU -Name "1" -Value "msedge.exe" -Type String -Force -ErrorAction Stop
            # Aktivace politiky (HKLM)
            $explPol = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
            $resultActivate = Invoke-RegistryOperation `
                -Path $explPol `
                -Name "DisallowRun" `
                -Value 1 `
                -Type "DWord" `
                -CreatePath
            if ($resultHKLM.Success -and $resultActivate.Success) {
                Write-Host "  ✅ DisallowRun aktivní (HKLM + HKCU)" -ForegroundColor Green
            }
            else {
                Write-Warning "DisallowRun částečně selhal."
            }
        }
        # --- Pro VARIANTU MEDIUM a HARDCORE: IFEO Kill-Switch ---
        if ($Variant -eq 'Medium' -or $Variant -eq 'Hardcore') {
            Write-Host "[6/?) Aplikuji IFEO Kill-Switch..." -ForegroundColor Yellow
            $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
            $debuggerValue = "C:\Windows\System32\systray.exe"
            $exesToBlock = @("msedge.exe", "msedgewebview2.exe", "MicrosoftEdgeUpdate.exe")
            $ifeoSuccessCount = 0
            foreach ($exe in $exesToBlock) {
                $exeKeyPath = Join-Path $ifeoPath $exe
                $result = Invoke-RegistryOperation `
                    -Path $exeKeyPath `
                    -Name "Debugger" `
                    -Value $debuggerValue `
                    -Type "String" `
                    -CreatePath
                if ($result.Success) {
                    Write-Host "  -> IFEO Kill-Switch: $exe" -ForegroundColor Gray
                    $ifeoSuccessCount++
                }
                else {
                    Write-Warning "Failed to set IFEO for ${exe}: $($result.Error)"
                }
            }
            Write-Host "  ✅ IFEO Kill-Switch aktivní ($ifeoSuccessCount/$($exesToBlock.Count) exe)" -ForegroundColor Green
        }
        # --- Pro VARIANTU MEDIUM a HARDCORE: Firewall ---
        if ($Variant -eq 'Medium' -or $Variant -eq 'Hardcore') {
            Write-Host "[7/?) Aplikuji Firewall blokaci..." -ForegroundColor Yellow
            $fwRuleName = "KRAKE-FIX - Block Edge"
            $existingRule = Get-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue
            if ($null -eq $existingRule) {
                New-NetFirewallRule -DisplayName $fwRuleName `
                    -Direction Outbound `
                    -Program "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" `
                    -Action Block `
                    -Profile Any `
                    -ErrorAction Stop | Out-Null
                Write-Host "  ✅ Firewall pravidlo vytvořeno" -ForegroundColor Green
            }
            else {
                Write-Host "  ✅ Firewall pravidlo již existuje" -ForegroundColor Green
            }
        }
        # --- Pro VARIANTU HARDCORE: ACL Lock ---
        if ($Variant -eq 'Hardcore') {
            Write-Host "[8/8] Aplikuji ACL Lock (DENY pro SYSTEM/TI)..." -ForegroundColor Red
            Write-Host "     ⚠️  VAROVÁNÍ: Toto je JEDNORÁZOVÉ! Bez watchdogů!" -ForegroundColor Yellow

            $confirm = Read-Host "Opravdu chcete aplikovat ACL Lock? (Ano/Ne)"
            if ($confirm -match '^a') {
                $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
                $exesToLock = @("msedge.exe", "msedgewebview2.exe", "MicrosoftEdgeUpdate.exe")

                foreach ($exe in $exesToLock) {
                    $exeKeyPath = Join-Path $ifeoPath $exe
                    # ═══════════════════════════════════════════════════════
                    # SECURITY: Input Validation (Defense-in-Depth)
                    # ═══════════════════════════════════════════════════════
                    # Validate that the computed path is within expected IFEO location
                    # Protection against path traversal/injection attacks
                    $expectedPathPrefix = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\"
                    if (-not $exeKeyPath.StartsWith($expectedPathPrefix)) {
                        Write-Error "SECURITY: Invalid IFEO path detected: $exeKeyPath (expected prefix: $expectedPathPrefix)"
                        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
                            Write-CoreLog -Message "SECURITY ALERT: Invalid IFEO path rejected during ACL Lock: $exeKeyPath" -Level Error
                        }
                        continue
                    }
                    if (Test-Path $exeKeyPath) {
                        # Audit log: ACL Lock attempt
                        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
                            Write-CoreLog -Message "Attempting ACL Lock (DENY SYSTEM/TI) for IFEO key: $exe" -Level Warning
                        }
                        # Apply ACL Lock with SYSTEM privilege escalation
                        $aclResult = Invoke-WithPrivilege -ScriptBlock {
                            param($keyPath)
                            # Get ACL (v SYSTEM context)
                            $acl = Get-Acl -Path $keyPath
                            # ═══════════════════════════════════════════════════════
                            # IDEMPOTENCE CHECK: Skip if DENY already exists
                            # ═══════════════════════════════════════════════════════
                            $existingSystemDeny = $acl.Access | Where-Object {
                                $_.AccessControlType -eq 'Deny' -and
                                $_.IdentityReference.Value -eq 'NT AUTHORITY\SYSTEM'
                            }
                            if ($null -ne $existingSystemDeny) {
                                Write-Host "  ℹ️  ACL Lock již existuje pro: $exe" -ForegroundColor Cyan
                                return $true  # Already locked, success
                            }
                            # DENY pro SYSTEM
                            $systemSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-18")
                            $systemDeny = [System.Security.AccessControl.RegistryAccessRule]::new(
                                $systemSid,
                                [System.Security.AccessControl.RegistryRights]::FullControl,
                                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
                                [System.Security.AccessControl.PropagationFlags]::None,
                                [System.Security.AccessControl.AccessControlType]::Deny
                            )
                            $acl.AddAccessRule($systemDeny)
                            # DENY pro TrustedInstaller
                            $tiSid = [System.Security.Principal.SecurityIdentifier]::new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
                            $tiDeny = [System.Security.AccessControl.RegistryAccessRule]::new(
                                $tiSid,
                                [System.Security.AccessControl.RegistryRights]::FullControl,
                                [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
                                [System.Security.AccessControl.PropagationFlags]::None,
                                [System.Security.AccessControl.AccessControlType]::Deny
                            )
                            $acl.AddAccessRule($tiDeny)
                            # Apply ACL (v SYSTEM context)
                            Set-Acl -Path $keyPath -AclObject $acl -ErrorAction Stop
                            return $true
                        } -ArgumentList @($exeKeyPath) -RequiredPrivilege 'System'
                        if ($aclResult.Success) {
                            Write-Host "  ✅ ACL Lock: $exe" -ForegroundColor Green
                            # Audit log: ACL Lock success
                            if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
                                Write-CoreLog -Message "ACL Lock applied successfully for IFEO key: $exe (DENY rules for SYSTEM and TrustedInstaller)" -Level Info
                            }
                        }
                        else {
                            Write-Warning "  ⚠️  ACL Lock failed for $exe : $($aclResult.Error)"
                            # Audit log: ACL Lock failure
                            if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
                                Write-CoreLog -Message "ACL Lock FAILED for IFEO key: $exe - Error: $($aclResult.Error)" -Level Error
                            }
                        }
                    }
                }
                Write-Host "  ✅ ACL Lock dokončen (8 vrstev)" -ForegroundColor Green
            }
            else {
                Write-Host "  ⚠️  ACL Lock zrušen uživatelem" -ForegroundColor Yellow
            }
        }
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host "  ✅ EDGE BLOCKADE DOKONČENA - Varianta: $Variant" -ForegroundColor Green
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
        if ($Variant -eq 'Hardcore') {
            Write-Host "⚠️  Pro odstranění ACL Lock použijte volbu [R] v menu!" -ForegroundColor Red
        }
        Write-Host ""
        # Audit log: Blockade success
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "Edge Blockade completed successfully: Variant=$Variant" -Level Info
        }
        Write-Host "Stiskněte Enter pro pokračování..." ; $null = Read-Host
    }
    catch {
        Write-Error "Chyba při aplikaci Edge Blockade: $($_.Exception.Message)"
        # Audit log: Blockade failure
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "Edge Blockade FAILED: Variant=$Variant, Error=$($_.Exception.Message)" -Level Error
        }
        Write-Host ""
        Write-Host "Stiskněte Enter pro pokračování..." ; $null = Read-Host
    }
}
<#
.SYNOPSIS
    Removes Microsoft Edge blockade.
.DESCRIPTION
    Two modes:
    - Standard: Removes IFEO, DisallowRun, Firewall (reverts Light/Medium)
    - ACL: Removes ACL DENY (reverts Hardcore) via SYSTEM Task Scheduler
.PARAMETER Mode
    Unlock mode: 'Standard' or 'ACL'
.EXAMPLE
    Invoke-EdgeUnlock -Mode 'Standard'
    Invoke-EdgeUnlock -Mode 'ACL'
.NOTES
    Based on KRAKE-FIX-v1.ps1 function Invoke-EdgeUnlock
    Per @STUDY/15-ACL-Inheritance-DACL-SACL.md (ACL unlock)
#>
function Invoke-EdgeUnlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Standard', 'ACL')]
        [string]$Mode
    )
    Clear-Host
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  EDGE UNLOCK - Mode: $Mode" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    # Audit log: Unlock start
    if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
        Write-CoreLog -Message "Edge Unlock initiated: Mode=$Mode, User=$env:USERNAME, Computer=$env:COMPUTERNAME" -Level Warning
    }
    try {
        if ($Mode -eq 'Standard') {
            # Standard unlock (Light/Medium variant)
            Write-Host "[1/3] Odstraňuji IFEO Kill-Switch..." -ForegroundColor Yellow
            $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
            $exesToUnlock = @("msedge.exe", "msedgewebview2.exe", "MicrosoftEdgeUpdate.exe")
            foreach ($exe in $exesToUnlock) {
                $exeKeyPath = Join-Path $ifeoPath $exe
                if (Test-Path $exeKeyPath) {
                    Remove-ItemProperty -Path $exeKeyPath -Name "Debugger" -Force -ErrorAction SilentlyContinue
                }
            }
            Write-Host "  ✅ IFEO odstraněn" -ForegroundColor Green
            Write-Host "[2/3] Odstraňuji DisallowRun..." -ForegroundColor Yellow
            Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "DisallowRun" -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "  ✅ DisallowRun odstraněn" -ForegroundColor Green
            Write-Host "[3/3] Odstraňuji Firewall blokaci..." -ForegroundColor Yellow
            $fwRuleName = "KRAKE-FIX - Block Edge"
            Remove-NetFirewallRule -DisplayName $fwRuleName -ErrorAction SilentlyContinue
            Write-Host "  ✅ Firewall pravidlo odstraněno" -ForegroundColor Green
        }
        elseif ($Mode -eq 'ACL') {
            # ACL unlock (Hardcore variant) - vyžaduje SYSTEM
            Write-Host "⚠️  ACL Unlock vyžaduje SYSTEM oprávnění!" -ForegroundColor Yellow
            Write-Host "    Spouštím s privilege escalation..." -ForegroundColor Yellow
            Write-Host ""
            $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
            $exesToUnlock = @("msedge.exe", "msedgewebview2.exe", "MicrosoftEdgeUpdate.exe")
            foreach ($exe in $exesToUnlock) {
                $exeKeyPath = Join-Path $ifeoPath $exe
                if (Test-Path $exeKeyPath) {
                    # Audit log: ACL Unlock attempt
                    if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
                        Write-CoreLog -Message "Attempting ACL Unlock (Remove DENY) for IFEO key: $exe" -Level Warning
                    }
                    # Remove ACL DENY rules with SYSTEM privilege escalation
                    $aclResult = Invoke-WithPrivilege -ScriptBlock {
                        param($keyPath)
                        # Get ACL (v SYSTEM context)
                        $acl = Get-Acl -Path $keyPath
                        # Remove DENY rules
                        $acl.Access | Where-Object { $_.AccessControlType -eq 'Deny' } | ForEach-Object {
                            $acl.RemoveAccessRule($_) | Out-Null
                        }
                        # Apply ACL (v SYSTEM context)
                        Set-Acl -Path $keyPath -AclObject $acl -ErrorAction Stop
                        return $true
                    } -ArgumentList @($exeKeyPath) -RequiredPrivilege 'System'
                    if ($aclResult.Success) {
                        Write-Host "  ✅ ACL Unlock: $exe" -ForegroundColor Green
                        # Audit log: ACL Unlock success
                        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
                            Write-CoreLog -Message "ACL Unlock successful for IFEO key: $exe (DENY rules removed)" -Level Info
                        }
                    }
                    else {
                        Write-Warning "  ⚠️  ACL Unlock failed for $exe : $($aclResult.Error)"
                        # Audit log: ACL Unlock failure
                        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
                            Write-CoreLog -Message "ACL Unlock FAILED for IFEO key: $exe - Error: $($aclResult.Error)" -Level Error
                        }
                    }
                }
            }
            Write-Host "  ✅ ACL Lock odstraněn" -ForegroundColor Green
        }
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host "  ✅ EDGE UNLOCK DOKONČEN" -ForegroundColor Green
        Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
        # Audit log: Unlock success
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "Edge Unlock completed successfully: Mode=$Mode" -Level Info
        }
        Write-Host "Stiskněte Enter pro pokračování..." ; $null = Read-Host
    }
    catch {
        Write-Error "Chyba při Edge Unlock: $($_.Exception.Message)"
        # Audit log: Unlock failure
        if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
            Write-CoreLog -Message "Edge Unlock FAILED: Mode=$Mode, Error=$($_.Exception.Message)" -Level Error
        }
        Write-Host ""
        Write-Host "Stiskněte Enter pro pokračování..." ; $null = Read-Host
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
    Show-EdgeBlockadeMenu
}
Export-ModuleMember -Function @(
    'Show-EdgeBlockadeMenu',
    'Show-EdgeBlockadeInfo',
    'Invoke-EdgeBlockade',
    'Invoke-EdgeUnlock',
    'Invoke-ModuleEntry'
)
# ═══════════════════════════════════════════════════════════════════════════
# MODULE INITIALIZATION LOG
# ═══════════════════════════════════════════════════════════════════════════
if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
    Write-CoreLog -Message "MEBlock.psm1 v$script:ModuleVersion loaded successfully" -Level Info
}