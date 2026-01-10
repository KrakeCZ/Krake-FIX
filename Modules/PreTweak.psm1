# KRAKE-FIX v2 - PRE-TWEAK DEPENDENCIES CHECK
# Module: PreTweak.psm1
# Version: 1.1.0 (Manual Mode + Dependency Test)
# ===========================================================
# ⚠️ Tento modul může měnit systémové nastavení.
# Používej pouze ve studijním / testovacím prostředí.
# Autor neručí za zneužití mimo akademické účely.
# ===========================================================
#Requires -Version 5.1
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
# Use Core module functions (Write-CoreLog, Invoke-AsSystem, etc.)
# Loaded by Main.ps1 - only import if running standalone
if (-not (Get-Command Write-CoreLog -ErrorAction SilentlyContinue)) {
    $CoreModule = Join-Path $PSScriptRoot 'Core.psm1'
    if (Test-Path $CoreModule) {
        Import-Module $CoreModule -Force -ErrorAction Stop
    }
    else {
        Write-Warning "Core.psm1 not found - some functionality unavailable"
    }
}
function Test-PsExecDependencies {
    <#
    .SYNOPSIS
        Check all PsExec and Schedule task dependencies.
    .DESCRIPTION
        Comprehensive check of all services required for:
        - PsExec64 SYSTEM escalation (RPC + SMB)
        - Schedule task fallback (Task Scheduler)
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    # Complete list of required services
    $requiredServices = @{
        # PsExec Core (RPC + SMB)
        'RpcSs'             = @{ Name = 'RPC'; Category = 'PsExec-Core'; Critical = $true }
        'DcomLaunch'        = @{ Name = 'DCOM Launch'; Category = 'PsExec-Core'; Critical = $true }
        'RpcEptMapper'      = @{ Name = 'RPC Endpoint Mapper'; Category = 'PsExec-Core'; Critical = $true }
        'LanmanServer'      = @{ Name = 'SMB Server (ADMIN$)'; Category = 'PsExec-SMB'; Critical = $true }
        'LanmanWorkstation' = @{ Name = 'SMB Client'; Category = 'PsExec-SMB'; Critical = $true }
        'Mup'               = @{ Name = 'Multiple UNC Provider'; Category = 'PsExec-SMB'; Critical = $false }
        'SamSs'             = @{ Name = 'Security Accounts Manager'; Category = 'PsExec-Auth'; Critical = $true }
        # Network Name Resolution
        'Dnscache'          = @{ Name = 'DNS Client'; Category = 'Network'; Critical = $false }
        'lmhosts'           = @{ Name = 'TCP/IP NetBIOS Helper'; Category = 'Network'; Critical = $false }
        # Fallback (Schedule task)
        'Schedule'          = @{ Name = 'Task Scheduler'; Category = 'Fallback'; Critical = $true }
    }
    $result = @{
        PsExecReady    = $false
        ScheduleReady  = $false
        ServicesStatus = @{}
        RunningCount   = 0
        DisabledCount  = 0
        StoppedCount   = 0
        Issues         = @()
    }
    foreach ($svcName in $requiredServices.Keys) {
        $svcInfo = $requiredServices[$svcName]
        try {
            $service = Get-Service -Name $svcName -ErrorAction Stop
            $status = @{
                DisplayName = $svcInfo.Name
                Category    = $svcInfo.Category
                Critical    = $svcInfo.Critical
                Status      = $service.Status
                StartType   = $service.StartType
                IsRunning   = ($service.Status -eq 'Running')
                IsDisabled  = ($service.StartType -eq 'Disabled')
            }
            $result.ServicesStatus[$svcName] = $status
            # Count statistics
            if ($status.IsRunning) { $result.RunningCount++ }
            if ($status.IsDisabled) { $result.DisabledCount++ }
            if ($service.Status -eq 'Stopped') { $result.StoppedCount++ }
            # Check critical issues
            if ($svcInfo.Critical) {
                if ($status.IsDisabled) {
                    $result.Issues += "$($svcInfo.Name) is DISABLED (critical for $($svcInfo.Category))"
                }
                if (-not $status.IsRunning) {
                    $result.Issues += "$($svcInfo.Name) is NOT RUNNING (critical for $($svcInfo.Category))"
                }
            }
        }
        catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
            $result.ServicesStatus[$svcName] = @{
                DisplayName = $svcInfo.Name
                Category    = $svcInfo.Category
                Critical    = $svcInfo.Critical
                Status      = 'NotFound'
                StartType   = 'Unknown'
                IsRunning   = $false
                IsDisabled  = $false
            }
            if ($svcInfo.Critical) {
                $result.Issues += "$($svcInfo.Name) service NOT FOUND"
            }
        }
        catch {
            # Catch other potential errors (like Access Denied, though RunAsAdmin should prevent this)
            $result.ServicesStatus[$svcName] = @{
                DisplayName = $svcInfo.Name
                Category    = $svcInfo.Category
                Critical    = $svcInfo.Critical
                Status      = 'Error'
                StartType   = 'Error'
                IsRunning   = $false
                IsDisabled  = $false
            }
            if ($svcInfo.Critical) {
                $result.Issues += "Error querying $($svcInfo.Name): $($_.Exception.Message)"
            }
        }
    }
    # Check ADMIN$ share
    try {
        $adminShare = Get-SmbShare -Name 'ADMIN$' -ErrorAction SilentlyContinue
        if ($null -eq $adminShare) {
            $result.Issues += "ADMIN$ share not available (SMB required for PsExec)"
        }
    }
    catch {
        $result.Issues += "Cannot query SMB shares"
    }
    # Determine readiness
    # Check critical services status
    $allPsExecCriticalRunning = $true
    if (-not $result.ServicesStatus['RpcSs'].IsRunning) { $allPsExecCriticalRunning = $false }
    if (-not $result.ServicesStatus['DcomLaunch'].IsRunning) { $allPsExecCriticalRunning = $false }
    if (-not $result.ServicesStatus['RpcEptMapper'].IsRunning) { $allPsExecCriticalRunning = $false }
    if (-not $result.ServicesStatus['LanmanServer'].IsRunning) { $allPsExecCriticalRunning = $false }
    if (-not $result.ServicesStatus['LanmanWorkstation'].IsRunning) { $allPsExecCriticalRunning = $false }
    if (-not $result.ServicesStatus['SamSs'].IsRunning) { $allPsExecCriticalRunning = $false }
    $result.PsExecReady = $allPsExecCriticalRunning
    $result.ScheduleReady = $result.ServicesStatus['Schedule'].IsRunning
    return $result
}
function Enable-PsExecDependencies {
    <#
    .SYNOPSIS
        Enable and start ALL services required for PsExec + Schedule task with SYSTEM privileges.
    .DESCRIPTION
        Activates complete dependency chain using NT\SYSTEM escalation:
        - PsExec Core: RpcSs, DcomLaunch, RpcEptMapper, SamSs
        - PsExec SMB: LanmanServer, LanmanWorkstation, Mup
        - Network: Dnscache, lmhosts
        - Fallback: Schedule (Task Scheduler)
        Uses Invoke-AsSystem for TrustedInstaller-protected services.
    .PARAMETER StartMode
        Startup type for disabled services: 'Automatic' (default) or 'Manual'
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [ValidateSet('Automatic', 'Manual')]
        [string]$StartMode = 'Automatic'
    )
    # Complete list of required services
    $requiredServices = @(
        # PsExec Core (RPC + SMB)
        'RpcSs',             # Remote Procedure Call
        'DcomLaunch',        # DCOM Server Process Launcher
        'RpcEptMapper',      # RPC Endpoint Mapper
        'LanmanServer',      # Server (for ADMIN$)
        'LanmanWorkstation', # Workstation (for SMB client)
        'Mup',               # Multiple UNC Provider
        'SamSs',             # Security Accounts Manager
        # Network Name Resolution
        'Dnscache',          # DNS Client
        'lmhosts',           # TCP/IP NetBIOS Helper
        # Fallback (Schedule task)
        'Schedule'           # Task Scheduler
    )
    $result = @{
        Success         = $false
        ServicesEnabled = @()
        ServicesStarted = @()
        Errors          = @()
        RestartRequired = $false
    }
    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor Cyan
    Write-Host "  AKTIVACE PSEXEC + SCHEDULE ZAVISLOSTI" -ForegroundColor Yellow
    Write-Host "==============================================================" -ForegroundColor Cyan
    Write-Host "  Cil: Zajistit funkcnost PsExec64 a Planovace uloh" -ForegroundColor Gray
    Write-Host "  Privilege: NT AUTHORITY\SYSTEM (pro TrustedInstaller sluzby)" -ForegroundColor Yellow
    Write-Host "  StartMode: $StartMode (pro Disabled sluzby)" -ForegroundColor Cyan
    Write-Host "==============================================================" -ForegroundColor Cyan
    Write-Host ""
    # ScriptBlock for SYSTEM execution
    $activateServicesBlock = {
        param([string[]]$ServiceList, [string]$StartupType)
        $localResult = @{
            SuccessCount    = 0
            EnabledServices = @()
            StartedServices = @()
            Errors          = @()
        }
        foreach ($serviceName in $ServiceList) {
            try {
                $service = Get-Service -Name $serviceName -ErrorAction Stop
                # 1. Fix StartType if Disabled
                if ($service.StartType -eq 'Disabled') {
                    try {
                        Set-Service -Name $serviceName -StartupType $StartupType -ErrorAction Stop
                        $localResult.EnabledServices += $serviceName
                    }
                    catch {
                        $localResult.Errors += "Cannot set StartupType for '$serviceName': $($_.Exception.Message)"
                    }
                }
                # 2. Start service if not running
                if ($service.Status -ne 'Running') {
                    try {
                        Start-Service -Name $serviceName -ErrorAction Stop
                        Start-Sleep -Milliseconds 500
                        $localResult.StartedServices += $serviceName
                        $localResult.SuccessCount++
                    }
                    catch {
                        $localResult.Errors += "Cannot start service '$serviceName': $($_.Exception.Message)"
                    }
                }
                else {
                    $localResult.SuccessCount++
                }
            }
            catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
                $localResult.Errors += "Service '$serviceName' not found in system"
            }
            catch {
                $localResult.Errors += "Unexpected error for '$serviceName': $($_.Exception.Message)"
            }
        }
        return $localResult
    }
    # Execute with SYSTEM privileges
    Write-Host "  [SYSTEM] Spoustim aktivaci s NT AUTHORITY\SYSTEM privilegii..." -ForegroundColor Cyan
    Write-Host ""
    try {
        $systemResult = Invoke-AsSystem -ScriptBlock $activateServicesBlock `
            -ArgumentList $requiredServices, $StartMode `
            -TimeoutSeconds 60
        if ($null -eq $systemResult) {
            Write-Host "  [WARNING] SYSTEM execution returned null, falling back to Admin..." -ForegroundColor Yellow
            # Fallback to direct Admin execution
            $systemResult = & $activateServicesBlock -ServiceList $requiredServices -StartupType $StartMode
        }
        # Process results
        $result.ServicesEnabled = $systemResult.EnabledServices
        $result.ServicesStarted = $systemResult.StartedServices
        $result.Errors = $systemResult.Errors
        $successCount = $systemResult.SuccessCount
        $totalCount = $requiredServices.Count
        if ($systemResult.EnabledServices.Count -gt 0) {
            $result.RestartRequired = $true
        }
    }
    catch {
        Write-Host "  [ERROR] SYSTEM execution failed: $($_.Exception.Message)" -ForegroundColor Red
        $result.Errors += "SYSTEM execution failed: $($_.Exception.Message)"
        $successCount = 0
        $totalCount = $requiredServices.Count
    }
    # Display detailed results
    Write-Host "  Zpracovavam vysledky aktivace..." -ForegroundColor Cyan
    Write-Host ""
    foreach ($serviceName in $requiredServices) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction Stop
            $wasEnabled = $serviceName -in $result.ServicesEnabled
            $wasStarted = $serviceName -in $result.ServicesStarted
            if ($service.Status -eq 'Running') {
                Write-Host "    [OK] $serviceName : $($service.StartType) / Running" -ForegroundColor Green
                if ($wasEnabled) { Write-Host "          -> Zmeneno z Disabled na Automatic" -ForegroundColor Gray }
                if ($wasStarted) { Write-Host "          -> Spusteno z Stopped" -ForegroundColor Gray }
            }
            elseif ($service.StartType -eq 'Disabled') {
                Write-Host "    [XX] $serviceName : Disabled / $($service.Status)" -ForegroundColor Red
            }
            else {
                Write-Host "    [!!] $serviceName : $($service.StartType) / $($service.Status)" -ForegroundColor Yellow
            }
        }
        catch {
            Write-Host "    [ERROR] $serviceName : Not found" -ForegroundColor Red
        }
    }
    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor Cyan
    Write-Host "  VYSLEDEK AKTIVACE (NT AUTHORITY\SYSTEM)" -ForegroundColor Yellow
    Write-Host "==============================================================" -ForegroundColor Cyan
    Write-Host "  Uspesne spusteno: $successCount / $totalCount sluzeb" -ForegroundColor $(if ($successCount -eq $totalCount) { "Green" } else { "Yellow" })
    Write-Host "  Zmen StartType: $($result.ServicesEnabled.Count)" -ForegroundColor Gray
    Write-Host "  Novych spustenych: $($result.ServicesStarted.Count)" -ForegroundColor Gray
    Write-Host "  Chyb: $($result.Errors.Count)" -ForegroundColor $(if ($result.Errors.Count -eq 0) { "Green" } else { "Red" })
    if ($result.Errors.Count -gt 0) {
        Write-Host ""
        Write-Host "  Detaily chyb:" -ForegroundColor Yellow
        foreach ($errorMsg in $result.Errors) {
            Write-Host "    - $errorMsg" -ForegroundColor Red
        }
    }
    Write-Host "==============================================================" -ForegroundColor Cyan
    Write-Host ""
    # Verify ADMIN$ share
    Write-Host "  Kontroluji ADMIN$ share..." -ForegroundColor Cyan
    Start-Sleep -Seconds 1
    try {
        $adminShare = Get-SmbShare -Name 'ADMIN$' -ErrorAction SilentlyContinue
        if ($null -ne $adminShare) {
            Write-Host "  [OK] ADMIN$ share je dostupny" -ForegroundColor Green
            $result.Success = ($successCount -ge ($totalCount * 0.8))  # 80% success rate
        }
        else {
            $result.Errors += "ADMIN$ share neni dostupny i pres bezici LanmanServer"
            Write-Host "  [WARNING] ADMIN$ share neni dostupny (mozna potreba restart)" -ForegroundColor Yellow
            $result.RestartRequired = $true
        }
    }
    catch {
        $result.Errors += "Cannot query ADMIN$ share: $($_.Exception.Message)"
        Write-Host "  [WARNING] Nelze overit ADMIN$ share" -ForegroundColor Yellow
    }
    if ($result.RestartRequired) {
        Write-Host ""
        Write-Host "  [TIP] DOPORUCENI: Restartujte PC pro uplnou aktivaci" -ForegroundColor Yellow
        Write-Host "        Po restartu spuste tweaky znovu" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "==============================================================" -ForegroundColor Cyan
    Write-Host ""
    return $result
}
function Show-PreTweakMenu {
    [CmdletBinding()]
    param()
    while ($true) {
        Clear-Host
        Write-Host ""
        Write-Host "==============================================================" -ForegroundColor Cyan
        Write-Host "  PRE-TWEAK - KONTROLA ZAVISLOSTI" -ForegroundColor Yellow
        Write-Host "==============================================================" -ForegroundColor Cyan
        Write-Host ""
        $status = Test-PsExecDependencies
        # Summary status
        Write-Host "  CELKOVY STAV:" -ForegroundColor Yellow
        Write-Host "    Sluzby: $($status.RunningCount) Running / $($status.DisabledCount) Disabled / $($status.StoppedCount) Stopped" -ForegroundColor Gray
        Write-Host ""
        # PsExec readiness
        $psexecIcon = if ($status.PsExecReady) { "OK" } else { "XX" }
        $psexecColor = if ($status.PsExecReady) { "Green" } else { "Red" }
        Write-Host "  [$psexecIcon] PsExec SYSTEM Escalation" -ForegroundColor $psexecColor
        # Schedule readiness
        $scheduleIcon = if ($status.ScheduleReady) { "OK" } else { "XX" }
        $scheduleColor = if ($status.ScheduleReady) { "Green" } else { "Red" }
        Write-Host "  [$scheduleIcon] Schedule Task Fallback" -ForegroundColor $scheduleColor
        Write-Host ""
        Write-Host "  DETAILNI STAV SLUZEB:" -ForegroundColor Yellow
        # Group by category
        $categories = @('PsExec-Core', 'PsExec-SMB', 'PsExec-Auth', 'Network', 'Fallback')
        foreach ($category in $categories) {
            $categoryServices = $status.ServicesStatus.GetEnumerator() | Where-Object { $_.Value.Category -eq $category }
            if ($categoryServices) {
                Write-Host ""
                Write-Host "    [$category]" -ForegroundColor Cyan
                foreach ($svc in $categoryServices) {
                    $svcData = $svc.Value
                    $icon = if ($svcData.IsRunning) { "OK" } elseif ($svcData.IsDisabled) { "XX" } else { "!!" }
                    $color = if ($svcData.IsRunning) { "Green" } elseif ($svcData.IsDisabled) { "Red" } else { "Yellow" }
                    $criticalMark = if ($svcData.Critical) { "*" } else { " " }
                    Write-Host "      [$icon]$criticalMark $($svcData.DisplayName): $($svcData.StartType) / $($svcData.Status)" -ForegroundColor $color
                }
            }
        }
        Write-Host ""
        Write-Host "    Legenda: [OK] Running | [XX] Disabled | [!!] Stopped | * = Critical" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "--------------------------------------------------------------" -ForegroundColor Cyan
        # Display issues
        if ($status.Issues.Count -gt 0) {
            Write-Host ""
            Write-Host "  KRITCKE PROBLEMY ($($status.Issues.Count)):" -ForegroundColor Red
            foreach ($issue in $status.Issues) {
                Write-Host "    - $issue" -ForegroundColor Yellow
            }
            Write-Host ""
            Write-Host "--------------------------------------------------------------" -ForegroundColor Cyan
        }
        Write-Host ""
        Write-Host "  [1] AKTIVOVAT VSECHNY ZAVISLOSTI (10 sluzeb)" -ForegroundColor White
        Write-Host "      -> RPC + SMB + DNS + Schedule" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [1] AKTIVOVAT ZAVISLOSTI (AUTOMATIC - auto-start pri restartu)" -ForegroundColor Green
        Write-Host "      -> Sluzby se nastavi na Automatic + spusti" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [2] AKTIVOVAT ZAVISLOSTI (MANUAL - jen docasne, bez auto-start)" -ForegroundColor Yellow
        Write-Host "      -> Sluzby se jen spusti, po restartu zustanou Disabled" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [3] TEST ZAVISLOSTI (bez zmeny - jen diagnostika)" -ForegroundColor Cyan
        Write-Host "      -> Overeni, zda PsExec a Schedule jsou ready" -ForegroundColor Gray
        Write-Host ""
        Write-Host "  [I] INFORMACE O PSEXEC ZAVISLOSTECH" -ForegroundColor White
        Write-Host ""
        Write-Host "  [Q] ZPET DO HLAVNIHO MENU" -ForegroundColor White
        Write-Host ""
        Write-Host "==============================================================" -ForegroundColor Cyan
        Write-Host ""
        $choice = Read-Host "Zadejte svou volbu"
        switch ($choice.ToUpper()) {
            '1' {
                Write-Host ""
                Write-Host "  [INFO] Rezim: AUTOMATIC (sluzby se nastavi na auto-start)" -ForegroundColor Cyan
                $testresult = Enable-PsExecDependencies -StartMode Automatic
                Write-Host ""
                Write-Host "  Stisknete klavesu pro pokracovani..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            }
            '2' {
                Write-Host ""
                Write-Host "  [INFO] Rezim: MANUAL (jen docasne spusteni, bez auto-start)" -ForegroundColor Cyan
                $testresult = Enable-PsExecDependencies -StartMode Manual
                Write-Host ""
                Write-Host "  Stisknete klavesu pro pokracovani..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            }
            '3' {
                Write-Host ""
                Write-Host "  [TEST] Spoustim diagnostiku zavislosti..." -ForegroundColor Cyan
                Write-Host ""
                $testResult = Test-PsExecDependencies
                Write-Host ""
                Write-Host "=== VYSLEDEK TESTU ===" -ForegroundColor Yellow
                Write-Host "  PsExec Ready:   $($testResult.PsExecReady)" -ForegroundColor $(if ($testResult.PsExecReady) { 'Green' }else { 'Red' })
                Write-Host "  Schedule Ready: $($testResult.ScheduleReady)" -ForegroundColor $(if ($testResult.ScheduleReady) { 'Green' }else { 'Red' })
                Write-Host "  Running:        $($testResult.RunningCount) / 10" -ForegroundColor Cyan
                Write-Host "  Disabled:       $($testResult.DisabledCount)" -ForegroundColor $(if ($testResult.DisabledCount -gt 0) { 'Yellow' }else { 'Green' })
                Write-Host "  Stopped:        $($testResult.StoppedCount)" -ForegroundColor $(if ($testResult.StoppedCount -gt 0) { 'Yellow' }else { 'Green' })
                Write-Host "  Issues:         $($testResult.Issues.Count)" -ForegroundColor $(if ($testResult.Issues.Count -gt 0) { 'Red' }else { 'Green' })
                if ($testResult.Issues.Count -gt 0) {
                    Write-Host ""
                    Write-Host "  Problemy:" -ForegroundColor Red
                    foreach ($issue in $testResult.Issues) {
                        Write-Host "    - $issue" -ForegroundColor Yellow
                    }
                }
                Write-Host ""
                Write-Host "  Stisknete klavesu pro pokracovani..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            }
            'I' {
                Clear-Host
                Write-Host ""
                Write-Host "==============================================================" -ForegroundColor Cyan
                Write-Host "  PSEXEC ZAVISLOSTI - VYSVETLENI" -ForegroundColor Yellow
                Write-Host "==============================================================" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  CO JE PSEXEC?" -ForegroundColor Cyan
                Write-Host "     PsExec (Sysinternals) umoznuje spoustet prikazy" -ForegroundColor Gray
                Write-Host "     s NT AUTHORITY SYSTEM privilegii" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  JAKE SLUZBY POTREBUJE?" -ForegroundColor Cyan
                Write-Host "     [PsExec-Core] RpcSs, DcomLaunch, RpcEptMapper, SamSs" -ForegroundColor Gray
                Write-Host "     [PsExec-SMB]  LanmanServer (ADMIN$), LanmanWorkstation, Mup" -ForegroundColor Gray
                Write-Host "     [Network]     Dnscache, lmhosts (rozliseni jmen)" -ForegroundColor Gray
                Write-Host "     [Fallback]    Schedule (Planovac uloh pro Invoke-AsSystem)" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  CO SE STANE BEZ SLUZEB?" -ForegroundColor Cyan
                Write-Host "     [X] PsExec SYSTEM escalation selze" -ForegroundColor Red
                Write-Host "     [V] Fallback na Invoke-AsSystem (Schedule task)" -ForegroundColor Green
                Write-Host "     [V] Fallback na Direct Admin (pokud staci)" -ForegroundColor Green
                Write-Host ""
                Write-Host "  KDY AKTIVOVAT?" -ForegroundColor Cyan
                Write-Host "     - Pred aplikaci TweakC (ultra aggressive debloat)" -ForegroundColor Gray
                Write-Host "     - Pokud vidite chyby 'Error creating key file'" -ForegroundColor Gray
                Write-Host "     - Kdyz chcete 100% spolehlivost SYSTEM escalation" -ForegroundColor Gray
                Write-Host ""
                Write-Host "  BEZPECNOST:" -ForegroundColor Cyan
                Write-Host "     Vsechny sluzby jsou standardni Windows komponenty" -ForegroundColor Gray
                Write-Host "     Po tweaku muzete znovu zakazat (TweakC to udela)" -ForegroundColor Gray
                Write-Host ""
                Write-Host "==============================================================" -ForegroundColor Cyan
                Write-Host ""
                Write-Host "  Stisknete klavesu pro navrat..." -ForegroundColor Gray
                $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            }
            'Q' {
                return
            }
            default {
                Write-Host ""
                Write-Host "  WARNING Neplatna volba Zkuste znovu" -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    }
}
function Invoke-ModuleEntry {
    [CmdletBinding()]
    param()
    Show-PreTweakMenu
}
Export-ModuleMember -Function @(
    'Test-PsExecDependencies',
    'Enable-PsExecDependencies',
    'Show-PreTweakMenu',
    'Invoke-ModuleEntry'
)
if (Get-Command Write-CoreLog -ErrorAction SilentlyContinue) {
    Write-CoreLog "PreTweak.psm1 v1.1.0 loaded successfully (Manual Mode + Test)" -Level INFO
}