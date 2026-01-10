# ===========================================================
# Modul: Updates.psm1
# Popis: Windows Update Management (Security/Default/Disable/Repair)
# Autor: KRAKE-FIX 
# ===========================================================
# ⚠️ Tento modul může měnit systémové nastavení.
# Používej pouze ve studijním / testovacím prostředí.
# Autor neručí za zneužití mimo akademické účely.
# ===========================================================
#Requires -Version 5.1
#Requires -RunAsAdministrator
# Import Core modulu pro privilege management (Invoke-AsSystem)
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
$script:ModuleName = 'Updates'
$script:ModuleVersion = '2.0.0'
$script:LogPath = Join-Path $env:TEMP "KRAKE-FIX-$script:ModuleName.log"
try {
    $isPresentationFrameworkLoaded = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'PresentationFramework' }
    if (-not $isPresentationFrameworkLoaded) {
        Add-Type -AssemblyName PresentationFramework -ErrorAction Stop
    }
}
catch {
    Write-Warning "PresentationFramework assembly could not be loaded: $($_.Exception.Message)"
}
# ===================================================================
# WINDOWS UPDATE MANAGEMENT FUNKCE
# ===================================================================
function Show-WindowsUpdateMenu {
    while ($true) {
        Clear-Host
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "      WINDOWS UPDATE MANAGEMENT" -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Vyberte akci:" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "[1] Nastavit Security Updates (Doporuceno)" -ForegroundColor Green
        Write-Host "    - Vypne automaticke ovladace" -ForegroundColor Gray
        Write-Host "    - Vypne automaticky restart" -ForegroundColor Gray
        Write-Host "    - Odlozi feature updates o 365 dni" -ForegroundColor Gray
        Write-Host "    - Odlozi quality updates o 4 dny" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[2] Vypnout JEN SLUZBY (Rizikove)" -ForegroundColor Yellow
        Write-Host "    - Vypne 5 WU sluzeb (wuauserv, BITS, UsoSvc, WaaSMedicSvc, DoSvc)" -ForegroundColor Gray
        Write-Host "    - Ovladace: Fungují manualne z Device Manager" -ForegroundColor Gray
        Write-Host "    - DLLs: NEDOTCENE (repair funguje)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[3] Vypnout JEN OVLADACE (Rizikove)" -ForegroundColor Yellow
        Write-Host "    - Vypne pouze automatickou instalaci ovladacu" -ForegroundColor Gray
        Write-Host "    - Sluzby: BEZI (security updates fungují!)" -ForegroundColor Gray
        Write-Host "    - Mene agresivni nez [1] Security Updates" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[4] Vypnout Windows Update (EXTREMNI!)" -ForegroundColor Red
        Write-Host "    - UPLNE vypne: Sluzby + Ovladace + DLLs + Cache + Tasks" -ForegroundColor Gray
        Write-Host "    - Pouze pro pokrocile uzivatele!" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[5] Obnovit vychozi nastaveni" -ForegroundColor Green
        Write-Host "    - Obnovi Windows Update na vyrobni nastaveni" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[6] Repair & Reset (Oprava Windows Update)" -ForegroundColor Magenta
        Write-Host "    - Opravi poskozene Windows Update" -ForegroundColor Gray
        Write-Host "    - Resetuje sluzby a cache" -ForegroundColor Gray
        Write-Host ""
        Write-Host "[B] Zpet do hlavniho menu" -ForegroundColor Red
        Write-Host ""
        $choice = Read-Host -Prompt "Zadejte svou volbu"
        switch ($choice) {
            '1' { Invoke-WPFUpdatessecurity }
            '2' { 
                Write-Host ""
                Write-Host "VAROVANI: Vypnuti Windows Update SLUZEB!" -ForegroundColor Yellow
                Write-Host "Security updates NEBUDOU stahovany!" -ForegroundColor Red
                Write-Host "Opravdu chcete pokracovat? (Y/N)" -ForegroundColor Yellow
                $confirm = Read-Host
                if ($confirm -eq 'Y' -or $confirm -eq 'y') {
                    Invoke-WPFUpdatesdisableServices
                }
            }
            '3' { 
                Write-Host ""
                Write-Host "Vypnuti automatickych OVLADACU..." -ForegroundColor Yellow
                Write-Host "Security updates BUDOU dale fungovat!" -ForegroundColor Green
                Write-Host "Opravdu chcete pokracovat? (Y/N)" -ForegroundColor Yellow
                $confirm = Read-Host
                if ($confirm -eq 'Y' -or $confirm -eq 'y') {
                    Invoke-WPFUpdatesdisableDrivers
                }
            }
            '4' { 
                Write-Host ""
                Write-Host "VAROVANI: UPLNE vypnuti Windows Update (EXTREMNI!)!" -ForegroundColor Red
                Write-Host "Toto je NEJAGRESIVNEJSI moznost!" -ForegroundColor Red
                Write-Host "Opravdu chcete pokracovat? (Y/N)" -ForegroundColor Yellow
                $confirm = Read-Host
                if ($confirm -eq 'Y' -or $confirm -eq 'y') {
                    Invoke-WPFUpdatesdisable
                }
            }
            '5' { Invoke-WPFUpdatesdefault }
            '6' { 
                Write-Host ""
                Write-Host "Spustit agresivni opravu? (Y/N)" -ForegroundColor Yellow
                Write-Host "(Agresivni oprava provadi take DISM a SFC scan - trva dele)" -ForegroundColor Gray
                $aggressive = Read-Host
                if ($aggressive -eq 'Y' -or $aggressive -eq 'y') {
                    Invoke-WPFFixesUpdate -Aggressive $true
                }
                else {
                    Invoke-WPFFixesUpdate -Aggressive $false
                }
            }
            'B' { return }
            default { 
                Write-Warning "Neplatna volba. Zkuste to znovu."
                Start-Sleep -Seconds 2
            }
        }
    }
}
function Invoke-WPFUpdatessecurity {
    <#
    .SYNOPSIS
        Sets Windows Update to recommended settings
    .DESCRIPTION
        1. Disables driver offering through Windows Update
        2. Disables Windows Update automatic restart
        3. Sets Windows Update to Semi-Annual Channel (Targeted)
        4. Defers feature updates for 365 days
        5. Defers quality updates for 4 days
    #>
    Write-Host "Disabling driver offering through Windows Update..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
    Write-Host "Disabling Windows Update automatic restart..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
    Write-Host "Disabled driver offering through Windows Update"
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -Type DWord -Value 20
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -Type DWord -Value 365
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -Type DWord -Value 4
    $ButtonType = [System.Windows.MessageBoxButton]::OK
    $MessageboxTitle = "Set Security Updates"
    $Messageboxbody = ("Recommended Update settings loaded")
    $MessageIcon = [System.Windows.MessageBoxImage]::Information
    [System.Windows.MessageBox]::Show($Messageboxbody, $MessageboxTitle, $ButtonType, $MessageIcon)
    Write-Host "================================="
    Write-Host "-- Updates Set to Recommended ---"
    Write-Host "================================="
}
function Invoke-WPFUpdatesdefault {
    <#
    .SYNOPSIS
        Resets Windows Update settings to default
    #>
    Write-Host "Restoring Windows Update registry settings..." -ForegroundColor Yellow
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 3
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
    # Reset WaaSMedicSvc registry settings to defaults
    Write-Host "Restoring WaaSMedicSvc settings..." -ForegroundColor Yellow
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" -Name "Start" -Type DWord -Value 3 -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" -Name "FailureActions" -Force -ErrorAction SilentlyContinue
    # Restore update services to their default state
    Write-Host "Restoring update services..." -ForegroundColor Yellow
    $services = @(
        @{Name = "BITS"; StartupType = "Manual" },
        @{Name = "wuauserv"; StartupType = "Manual" },
        @{Name = "UsoSvc"; StartupType = "Automatic" },
        @{Name = "uhssvc"; StartupType = "Disabled" },
        @{Name = "WaaSMedicSvc"; StartupType = "Manual" }
    )
    foreach ($service in $services) {
        try {
            Write-Host "Restoring $($service.Name) to $($service.StartupType)..."
            $serviceObj = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
            if ($serviceObj) {
                # POUŽITÍ REGISTRY PŘÍSTUPU (spolehlivější)
                $startValue = switch ($service.StartupType) {
                    'Disabled' { 4 }
                    'Manual' { 3 }
                    'Automatic' { 2 }
                    default { 3 }
                }
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
                if (Test-Path $regPath) {
                    Set-ItemProperty -Path $regPath -Name "Start" -Value $startValue -Type DWord -Force -ErrorAction SilentlyContinue
                }
                # Reset failure actions to default using sc command
                Start-Process -FilePath "sc.exe" -ArgumentList "failure `"$($service.Name)`" reset= 86400 actions= restart/60000/restart/60000/restart/60000" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
                # Start the service if it should be running
                if ($service.StartupType -eq "Automatic") {
                    Start-Service -Name $service.Name -ErrorAction SilentlyContinue
                }
            }
        }
        catch {
            Write-Host "Warning: Could not restore service $($service.Name) - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    # Restore renamed DLLs if they exist
    Write-Host "Restoring renamed update service DLLs..." -ForegroundColor Yellow
    $dlls = @("WaaSMedicSvc", "wuaueng")
    foreach ($dll in $dlls) {
        $dllPath = "C:\Windows\System32\$dll.dll"
        $backupPath = "C:\Windows\System32\${dll}_BAK.dll"
        if ((Test-Path $backupPath) -and !(Test-Path $dllPath)) {
            try {
                # Take ownership of backup file
                Start-Process -FilePath "takeown.exe" -ArgumentList "/f `"$backupPath`"" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
                # Grant full control to everyone
                Start-Process -FilePath "icacls.exe" -ArgumentList "`"$backupPath`" /grant *S-1-1-0:F" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
                # Rename back to original
                Rename-Item -Path $backupPath -NewName "$dll.dll" -ErrorAction SilentlyContinue
                Write-Host "Restored ${dll}_BAK.dll to $dll.dll"
                # Restore ownership to TrustedInstaller
                Start-Process -FilePath "icacls.exe" -ArgumentList "`"$dllPath`" /setowner `"NT SERVICE\TrustedInstaller`"" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
                Start-Process -FilePath "icacls.exe" -ArgumentList "`"$dllPath`" /remove *S-1-1-0" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
            }
            catch {
                Write-Host "Warning: Could not restore $dll.dll - $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
    # Enable update related scheduled tasks
    Write-Host "Enabling update related scheduled tasks..." -ForegroundColor Yellow
    $taskPaths = @(
        '\Microsoft\Windows\InstallService\*'
        '\Microsoft\Windows\UpdateOrchestrator\*'
        '\Microsoft\Windows\UpdateAssistant\*'
        '\Microsoft\Windows\WaaSMedic\*'
        '\Microsoft\Windows\WindowsUpdate\*'
        '\Microsoft\WindowsUpdate\*'
    )
    foreach ($taskPath in $taskPaths) {
        try {
            $tasks = Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue
            foreach ($task in $tasks) {
                Enable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                Write-Host "Enabled task: $($task.TaskName)"
            }
        }
        catch {
            Write-Host "Warning: Could not enable tasks in path $taskPath - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    Write-Host "Enabling driver offering through Windows Update..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
    Write-Host "Enabling Windows Update automatic restart..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue
    Write-Host "Enabled driver offering through Windows Update"
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue
    Write-Host "==================================================="
    Write-Host "---  Windows Update Settings Reset to Default   ---"
    Write-Host "==================================================="
    Start-Process -FilePath "secedit" -ArgumentList "/configure /cfg $env:windir\inf\defltbase.inf /db defltbase.sdb /verbose" -Wait
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c RD /S /Q $env:WinDir\System32\GroupPolicyUsers" -Wait
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c RD /S /Q $env:WinDir\System32\GroupPolicy" -Wait
    Start-Process -FilePath "gpupdate" -ArgumentList "/force" -Wait
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\Microsoft\WindowsSelfHost" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Microsoft\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Microsoft\WindowsSelfHost" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\WOW6432Node\Microsoft\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "==================================================="
    Write-Host "---  Windows Local Policies Reset to Default   ---"
    Write-Host "==================================================="
    Write-Host "Note: A system restart may be required for all changes to take full effect." -ForegroundColor Yellow
}
function Invoke-WPFUpdatesdisable {
    <#
    .SYNOPSIS
        Disables Windows Update
    .NOTES
        Disabling Windows Update is not recommended. This is only for advanced users who know what they are doing.
        This function requires administrator privileges and will attempt to run as SYSTEM for certain operations.
    #>
    Write-Host "Configuring registry settings..." -ForegroundColor Yellow
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Type DWord -Value 1
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 0
    # Additional registry settings
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" -Name "Start" -Type DWord -Value 4 -Force -ErrorAction SilentlyContinue
    $failureActions = [byte[]](0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xd4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x93, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" -Name "FailureActions" -Type Binary -Value $failureActions -Force -ErrorAction SilentlyContinue
    # Disable and stop update related services
    Write-Host "Disabling update services..." -ForegroundColor Yellow
    $services = @(
        "BITS"
        "wuauserv"
        "UsoSvc"
        "uhssvc"
        "WaaSMedicSvc"
    )
    foreach ($service in $services) {
        try {
            Write-Host "Stopping and disabling $service..."
            $serviceObj = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($serviceObj) {
                Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                # POUŽITÍ REGISTRY PŘÍSTUPU (stejně jako V1)
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$service"
                if (Test-Path $regPath) {
                    Set-ItemProperty -Path $regPath -Name "Start" -Value 4 -Type DWord -Force -ErrorAction SilentlyContinue
                }
                # Set failure actions to nothing using sc command
                Start-Process -FilePath "sc.exe" -ArgumentList "failure `"$service`" reset= 0 actions= `"`"" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Host "Warning: Could not process service $service - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    # Rename critical update service DLLs (requires SYSTEM privileges)
    Write-Host "Attempting to rename critical update service DLLs..." -ForegroundColor Yellow
    $dlls = @("WaaSMedicSvc", "wuaueng")
    foreach ($dll in $dlls) {
        $dllPath = "C:\Windows\System32\$dll.dll"
        $backupPath = "C:\Windows\System32\${dll}_BAK.dll"
        if (Test-Path $dllPath) {
            try {
                # Take ownership
                Start-Process -FilePath "takeown.exe" -ArgumentList "/f `"$dllPath`"" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
                # Grant full control to everyone
                Start-Process -FilePath "icacls.exe" -ArgumentList "`"$dllPath`" /grant *S-1-1-0:F" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
                # Rename file
                if (!(Test-Path $backupPath)) {
                    Rename-Item -Path $dllPath -NewName "${dll}_BAK.dll" -ErrorAction SilentlyContinue
                    Write-Host "Renamed $dll.dll to ${dll}_BAK.dll"
                    # Restore ownership to TrustedInstaller
                    Start-Process -FilePath "icacls.exe" -ArgumentList "`"$backupPath`" /setowner `"NT SERVICE\TrustedInstaller`"" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
                    Start-Process -FilePath "icacls.exe" -ArgumentList "`"$backupPath`" /remove *S-1-1-0" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-Host "Warning: Could not rename $dll.dll - $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
    # Delete downloaded update files
    Write-Host "Cleaning up downloaded update files..." -ForegroundColor Yellow
    try {
        $softwareDistPath = "C:\Windows\SoftwareDistribution"
        if (Test-Path $softwareDistPath) {
            Get-ChildItem -Path $softwareDistPath -Recurse -Force | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
            Write-Host "Cleared SoftwareDistribution folder"
        }
    }
    catch {
        Write-Host "Warning: Could not fully clear SoftwareDistribution folder - $($_.Exception.Message)" -ForegroundColor Yellow
    }
    # Disable update related scheduled tasks
    Write-Host "Disabling update related scheduled tasks..." -ForegroundColor Yellow
    $taskPaths = @(
        '\Microsoft\Windows\InstallService\*'
        '\Microsoft\Windows\UpdateOrchestrator\*'
        '\Microsoft\Windows\UpdateAssistant\*'
        '\Microsoft\Windows\WaaSMedic\*'
        '\Microsoft\Windows\WindowsUpdate\*'
        '\Microsoft\WindowsUpdate\*'
    )
    foreach ($taskPath in $taskPaths) {
        try {
            $tasks = Get-ScheduledTask -TaskPath $taskPath -ErrorAction SilentlyContinue
            foreach ($task in $tasks) {
                Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                Write-Host "Disabled task: $($task.TaskName)"
            }
        }
        catch {
            Write-Host "Warning: Could not disable tasks in path $taskPath - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
    Write-Host "=================================" -ForegroundColor Green
    Write-Host "---   Updates ARE DISABLED    ---" -ForegroundColor Green
    Write-Host "===================================" -ForegroundColor Green
    Write-Host "Note: Some operations may require a system restart to take full effect." -ForegroundColor Yellow
    $ButtonType = [System.Windows.MessageBoxButton]::OK
    $MessageboxTitle = "Windows Update Disabled"
    $Messageboxbody = ("Windows Update has been completely disabled.`nSome operations may require a system restart.")
    $MessageIcon = [System.Windows.MessageBoxImage]::Information
    [System.Windows.MessageBox]::Show($Messageboxbody, $MessageboxTitle, $ButtonType, $MessageIcon)
}
function Invoke-WPFSystemRepair {
    <#
    .SYNOPSIS
        Checks for system corruption using Chkdsk, SFC, and DISM
    .DESCRIPTION
        1. Chkdsk    - Fixes disk and filesystem corruption
        2. SFC Run 1 - Fixes system file corruption, and fixes DISM if it was corrupted
        3. DISM      - Fixes system image corruption, and fixes SFC's system image if it was corrupted
        4. SFC Run 2 - Fixes system file corruption, this time with an almost guaranteed uncorrupted system image
    #>
    function Invoke-Chkdsk {
        param([int]$parentProgressId = 0)
        Write-Host "`n[CHKDSK] Skenování disku..." -ForegroundColor Yellow
        $oldpercent = 0
        chkdsk.exe /scan /perf 2>&1 | ForEach-Object {
            if ($_ -match "%.*?(\d+)%") {
                [int]$percent = $matches[1]
                if ($percent -gt $oldpercent) {
                    Write-Host "  -> Chkdsk: $percent%" -ForegroundColor Gray
                    $oldpercent = $percent
                }
            }
        }
        Write-Host "[CHKDSK] Dokončeno`n" -ForegroundColor Green
    }
    function Invoke-SFC {
        param([int]$parentProgressId = 0)
        Write-Host "`n[SFC] System File Check..." -ForegroundColor Yellow
        $oldpercent = 0
        & {
            $ErrorActionPreference = "SilentlyContinue"
            sfc.exe /scannow 2>&1 | ForEach-Object {
                if ($_ -ne "") {
                    $utf8line = $_ -replace "`0", ""
                    if ($utf8line -match "(\d+)\s*%") {
                        [int]$percent = $matches[1]
                        if ($percent -gt $oldpercent) {
                            Write-Host "  -> SFC: $percent%" -ForegroundColor Gray
                            $oldpercent = $percent
                        }
                    }
                }
            }
        }
        Write-Host "[SFC] Dokončeno`n" -ForegroundColor Green
    }
    function Invoke-DISM {
        param([int]$parentProgressId = 0)
        Write-Host "`n[DISM] Oprava system image..." -ForegroundColor Yellow
        $oldpercent = 0
        DISM /Online /Cleanup-Image /RestoreHealth | ForEach-Object {
            if ($_ -match "(\d+)[.,]\d+%") {
                [int]$percent = $matches[1]
                if ($percent -gt $oldpercent) {
                    Write-Host "  -> DISM: $percent%" -ForegroundColor Gray
                    $oldpercent = $percent
                }
            }
        }
        Write-Host "[DISM] Dokončeno`n" -ForegroundColor Green
    }
    try {
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host "      SYSTÉMOVÁ OPRAVA (CHKDSK + SFC + DISM)" -ForegroundColor Cyan
        Write-Host "==================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Warning "Tato operace může trvat 30-60 minut nebo déle!"
        Write-Host ""
        # Step 1: Run chkdsk
        Invoke-Chkdsk
        # Step 2: Run SFC (první průchod)
        Invoke-SFC
        # Step 3: Run DISM
        Invoke-DISM
        # Step 4: Run SFC (druhý průchod)
        Write-Host "Spouštím SFC druhý průchod (s opraveným image)..." -ForegroundColor Yellow
        Invoke-SFC
        Write-Host ""
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host "    SYSTÉMOVÁ OPRAVA DOKONČENA" -ForegroundColor Green
        Write-Host "==================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "DŮLEŽITÉ: Doporučuje se RESTARTOVAT PC!" -ForegroundColor Yellow
    }
    catch {
        Write-Error "Chyba při opravě systému: $_"
    }
}
function Invoke-WPFFixesUpdate {
    <#
    .SYNOPSIS
        Performs various tasks in an attempt to repair Windows Update
    .DESCRIPTION
        1. (Aggressive Only) Scans the system for corruption using the Invoke-WPFSystemRepair function
        2. Stops Windows Update Services
        3. Remove the QMGR Data file, which stores BITS jobs
        4. (Aggressive Only) Renames the DataStore and CatRoot2 folders
            DataStore - Contains the Windows Update History and Log Files
            CatRoot2 - Contains the Signatures for Windows Update Packages
        5. Renames the Windows Update Download Folder
        6. Deletes the Windows Update Log
        7. (Aggressive Only) Resets the Security Descriptors on the Windows Update Services
        8. Reregisters the BITS and Windows Update DLLs
        9. Removes the WSUS client settings
        10. Resets WinSock
        11. Gets and deletes all BITS jobs
        12. Sets the startup type of the Windows Update Services then starts them
        13. Forces Windows Update to check for updates
    .PARAMETER Aggressive
        If specified, the script will take additional steps to repair Windows Update that are more dangerous, take a significant amount of time, or are generally unnecessary
    #>
    param($Aggressive = $false)
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -PercentComplete 0
    Set-WinUtilTaskbaritem -state "Indeterminate" -overlay "logo"
    Write-Host "Starting Windows Update Repair..."
    # Wait for the first progress bar to show, otherwise the second one won't show
    Start-Sleep -Milliseconds 200
    if ($Aggressive) {
        Invoke-WPFSystemRepair
    }
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Stopping Windows Update Services..." -PercentComplete 10
    # Stop the Windows Update Services
    Write-Progress -Id 2 -ParentId 0 -Activity "Stopping Services" -Status "Stopping BITS..." -PercentComplete 0
    Stop-Service -Name BITS -Force
    Write-Progress -Id 2 -ParentId 0 -Activity "Stopping Services" -Status "Stopping wuauserv..." -PercentComplete 20
    Stop-Service -Name wuauserv -Force
    Write-Progress -Id 2 -ParentId 0 -Activity "Stopping Services" -Status "Stopping appidsvc..." -PercentComplete 40
    Stop-Service -Name appidsvc -Force
    Write-Progress -Id 2 -ParentId 0 -Activity "Stopping Services" -Status "Stopping cryptsvc..." -PercentComplete 60
    Stop-Service -Name cryptsvc -Force
    Write-Progress -Id 2 -ParentId 0 -Activity "Stopping Services" -Status "Completed" -PercentComplete 100
    # Remove the QMGR Data file
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Renaming/Removing Files..." -PercentComplete 20
    Write-Progress -Id 3 -ParentId 0 -Activity "Renaming/Removing Files" -Status "Removing QMGR Data files..." -PercentComplete 0
    Remove-Item "$env:allusersprofile\Application Data\Microsoft\Network\Downloader\qmgr*.dat" -ErrorAction SilentlyContinue
    if ($Aggressive) {
        # Rename the Windows Update Log and Signature Folders
        Write-Progress -Id 3 -ParentId 0 -Activity "Renaming/Removing Files" -Status "Renaming the Windows Update Log, Download, and Signature Folder..." -PercentComplete 20
        Rename-Item $env:systemroot\SoftwareDistribution\DataStore DataStore.bak -ErrorAction SilentlyContinue
        Rename-Item $env:systemroot\System32\Catroot2 catroot2.bak -ErrorAction SilentlyContinue
    }
    # Rename the Windows Update Download Folder
    Write-Progress -Id 3 -ParentId 0 -Activity "Renaming/Removing Files" -Status "Renaming the Windows Update Download Folder..." -PercentComplete 20
    Rename-Item $env:systemroot\SoftwareDistribution\Download Download.bak -ErrorAction SilentlyContinue
    # Delete the legacy Windows Update Log
    Write-Progress -Id 3 -ParentId 0 -Activity "Renaming/Removing Files" -Status "Removing the old Windows Update log..." -PercentComplete 80
    Remove-Item $env:systemroot\WindowsUpdate.log -ErrorAction SilentlyContinue
    Write-Progress -Id 3 -ParentId 0 -Activity "Renaming/Removing Files" -Status "Completed" -PercentComplete 100
    if ($Aggressive) {
        # Reset the Security Descriptors on the Windows Update Services
        Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Resetting the WU Service Security Descriptors..." -PercentComplete 25
        Write-Progress -Id 4 -ParentId 0 -Activity "Resetting the WU Service Security Descriptors" -Status "Resetting the BITS Security Descriptor..." -PercentComplete 0
        Start-Process -NoNewWindow -FilePath "sc.exe" -ArgumentList "sdset", "bits", "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)" -Wait
        Write-Progress -Id 4 -ParentId 0 -Activity "Resetting the WU Service Security Descriptors" -Status "Resetting the wuauserv Security Descriptor..." -PercentComplete 50
        Start-Process -NoNewWindow -FilePath "sc.exe" -ArgumentList "sdset", "wuauserv", "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;PU)" -Wait
        Write-Progress -Id 4 -ParentId 0 -Activity "Resetting the WU Service Security Descriptors" -Status "Completed" -PercentComplete 100
    }
    # Reregister the BITS and Windows Update DLLs
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Reregistering DLLs..." -PercentComplete 40
    $oldLocation = Get-Location
    Set-Location $env:systemroot\system32
    $i = 0
    $DLLs = @(
        "atl.dll", "urlmon.dll", "mshtml.dll", "shdocvw.dll", "browseui.dll",
        "jscript.dll", "vbscript.dll", "scrrun.dll", "msxml.dll", "msxml3.dll",
        "msxml6.dll", "actxprxy.dll", "softpub.dll", "wintrust.dll", "dssenh.dll",
        "rsaenh.dll", "gpkcsp.dll", "sccbase.dll", "slbcsp.dll", "cryptdlg.dll",
        "oleaut32.dll", "ole32.dll", "shell32.dll", "initpki.dll", "wuapi.dll",
        "wuaueng.dll", "wuaueng1.dll", "wucltui.dll", "wups.dll", "wups2.dll",
        "wuweb.dll", "qmgr.dll", "qmgrprxy.dll", "wucltux.dll", "muweb.dll", "wuwebv.dll"
    )
    foreach ($dll in $DLLs) {
        Write-Progress -Id 5 -ParentId 0 -Activity "Reregistering DLLs" -Status "Registering $dll..." -PercentComplete ($i / $DLLs.Count * 100)
        $i++
        Start-Process -NoNewWindow -FilePath "regsvr32.exe" -ArgumentList "/s", $dll
    }
    Set-Location $oldLocation
    Write-Progress -Id 5 -ParentId 0 -Activity "Reregistering DLLs" -Status "Completed" -PercentComplete 100
    # Remove the WSUS client settings
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate") {
        Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Removing WSUS client settings..." -PercentComplete 60
        Write-Progress -Id 6 -ParentId 0 -Activity "Removing WSUS client settings" -PercentComplete 0
        Start-Process -NoNewWindow -FilePath "REG" -ArgumentList "DELETE", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate", "/v", "AccountDomainSid", "/f" -RedirectStandardError "NUL"
        Start-Process -NoNewWindow -FilePath "REG" -ArgumentList "DELETE", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate", "/v", "PingID", "/f" -RedirectStandardError "NUL"
        Start-Process -NoNewWindow -FilePath "REG" -ArgumentList "DELETE", "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate", "/v", "SusClientId", "/f" -RedirectStandardError "NUL"
        Write-Progress -Id 6 -ParentId 0 -Activity "Removing WSUS client settings" -Status "Completed" -PercentComplete 100
    }
    # Remove Group Policy Windows Update settings
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Removing Group Policy Windows Update settings..." -PercentComplete 60
    Write-Progress -Id 7 -ParentId 0 -Activity "Removing Group Policy Windows Update settings" -PercentComplete 0
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
    Write-Host "Defaulting driver offering through Windows Update..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
    Write-Host "Defaulting Windows Update automatic restart..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -ErrorAction SilentlyContinue
    Write-Host "Clearing ANY Windows Update Policy settings..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "BranchReadinessLevel" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferFeatureUpdatesPeriodInDays" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "DeferQualityUpdatesPeriodInDays" -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\Microsoft\WindowsSelfHost" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Microsoft\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Microsoft\WindowsSelfHost" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\WOW6432Node\Microsoft\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" -Recurse -Force -ErrorAction SilentlyContinue
    Start-Process -NoNewWindow -FilePath "secedit" -ArgumentList "/configure", "/cfg", "$env:windir\inf\defltbase.inf", "/db", "defltbase.sdb", "/verbose" -Wait
    Start-Process -NoNewWindow -FilePath "cmd.exe" -ArgumentList "/c RD /S /Q $env:WinDir\System32\GroupPolicyUsers" -Wait
    Start-Process -NoNewWindow -FilePath "cmd.exe" -ArgumentList "/c RD /S /Q $env:WinDir\System32\GroupPolicy" -Wait
    Start-Process -NoNewWindow -FilePath "gpupdate" -ArgumentList "/force" -Wait
    Write-Progress -Id 7 -ParentId 0 -Activity "Removing Group Policy Windows Update settings" -Status "Completed" -PercentComplete 100
    # Reset WinSock
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Resetting WinSock..." -PercentComplete 65
    Write-Progress -Id 7 -ParentId 0 -Activity "Resetting WinSock" -Status "Resetting WinSock..." -PercentComplete 0
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "winsock", "reset"
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "winhttp", "reset", "proxy"
    Start-Process -NoNewWindow -FilePath "netsh" -ArgumentList "int", "ip", "reset"
    Write-Progress -Id 7 -ParentId 0 -Activity "Resetting WinSock" -Status "Completed" -PercentComplete 100
    # Get and delete all BITS jobs (MOVED TO BEGINNING - before stopping services)
    # Change the startup type of the Windows Update Services and start them
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Starting Windows Update Services..." -PercentComplete 90
    Write-Progress -Id 9 -ParentId 0 -Activity "Starting Windows Update Services" -Status "Starting BITS..." -PercentComplete 0
    Get-Service BITS | Set-Service -StartupType Manual -PassThru | Start-Service
    Write-Progress -Id 9 -ParentId 0 -Activity "Starting Windows Update Services" -Status "Starting wuauserv..." -PercentComplete 25
    Get-Service wuauserv | Set-Service -StartupType Manual -PassThru | Start-Service
    Write-Progress -Id 9 -ParentId 0 -Activity "Starting Windows Update Services" -Status "Starting AppIDSvc..." -PercentComplete 50
    # The AppIDSvc service is protected, so the startup type has to be changed in the registry
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\AppIDSvc" -Name "Start" -Value 3
    Start-Service AppIDSvc
    Write-Progress -Id 9 -ParentId 0 -Activity "Starting Windows Update Services" -Status "Starting CryptSvc..." -PercentComplete 75
    Get-Service CryptSvc | Set-Service -StartupType Manual -PassThru | Start-Service
    Write-Progress -Id 9 -ParentId 0 -Activity "Starting Windows Update Services" -Status "Completed" -PercentComplete 100
    # Force Windows Update to check for updates
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Forcing discovery..." -PercentComplete 95
    Write-Progress -Id 10 -ParentId 0 -Activity "Forcing discovery" -Status "Forcing discovery..." -PercentComplete 0
    try {
        (New-Object -ComObject Microsoft.Update.AutoUpdate).DetectNow()
    }
    catch {
        Set-WinUtilTaskbaritem -state "Error" -overlay "warning"
        Write-Warning "Failed to create Windows Update COM object: $_"
    }
    Start-Process -NoNewWindow -FilePath "wuauclt" -ArgumentList "/resetauthorization", "/detectnow"
    Write-Progress -Id 10 -ParentId 0 -Activity "Forcing discovery" -Status "Completed" -PercentComplete 100
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Status "Completed" -PercentComplete 100
    Set-WinUtilTaskbaritem -state "None" -overlay "checkmark"
    $ButtonType = [System.Windows.MessageBoxButton]::OK
    $MessageboxTitle = "Reset Windows Update "
    $Messageboxbody = ("Stock settings loaded.`n Please reboot your computer")
    $MessageIcon = [System.Windows.MessageBoxImage]::Information
    [System.Windows.MessageBox]::Show($Messageboxbody, $MessageboxTitle, $ButtonType, $MessageIcon)
    Write-Host "==============================================="
    Write-Host "-- Reset All Windows Update Settings to Stock -"
    Write-Host "==============================================="
    # Remove the progress bars
    Write-Progress -Id 0 -Activity "Repairing Windows Update" -Completed
    Write-Progress -Id 1 -Activity "Scanning for corruption" -Completed
    Write-Progress -Id 2 -Activity "Stopping Services" -Completed
    Write-Progress -Id 3 -Activity "Renaming/Removing Files" -Completed
    Write-Progress -Id 4 -Activity "Resetting the WU Service Security Descriptors" -Completed
    Write-Progress -Id 5 -Activity "Reregistering DLLs" -Completed
    Write-Progress -Id 6 -Activity "Removing Group Policy Windows Update settings" -Completed
    Write-Progress -Id 7 -Activity "Resetting WinSock" -Completed
    Write-Progress -Id 8 -Activity "Deleting BITS jobs" -Completed
    Write-Progress -Id 9 -Activity "Starting Windows Update Services" -Completed
    Write-Progress -Id 10 -Activity "Forcing discovery" -Completed
}
# ═══════════════════════════════════════════════════════════════════════════
# GRANULAR WINDOWS UPDATE CONTROL 
# ═══════════════════════════════════════════════════════════════════════════
# Purpose: Allow user to disable ONLY services OR ONLY drivers (not both)
# Use case: User wants to control WU updates without full nuclear disable
# ═══════════════════════════════════════════════════════════════════════════
function Invoke-WPFUpdatesdisableServices {
    <#
    .SYNOPSIS
        Disables ONLY Windows Update services (leaves driver installation enabled)
    .DESCRIPTION
        **GRANULAR CONTROL - Option [2.1] from v1 Security Hazard Menu**
        Disables ONLY the 5 core Windows Update services:
        - wuauserv (Windows Update)
        - BITS (Background Intelligent Transfer Service)
        - UsoSvc (Update Orchestrator Service)
        - WaaSMedicSvc (Windows as a Service Medic)
        - DoSvc (Delivery Optimization)
        **DIFFERENCE vs. Full Disable WU:**
        - Services: ❌ Disabled (no automatic updates)
        - Drivers: ✅ Can still be installed manually from Device Manager
        - DLLs: ✅ NOT renamed (repair is still possible)
        - Cache: ✅ NOT cleared
        - Tasks: ✅ NOT disabled
        **USE CASE:**
        User wants to stop automatic Windows Updates but still be able to
        install drivers manually. Less aggressive than full WU disable.
    .NOTES
        Reference: KRAKE-FIX-v1.ps1 lines 13010-13032
        Privilege: SYSTEM (required for service registry manipulation)
        ⚠️ This disables Windows security updates! Use with caution!
    #>
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host "  ⚠️ DISABLE WINDOWS UPDATE SERVICES ONLY" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "This will disable 5 Windows Update services:" -ForegroundColor White
    Write-Host "  • wuauserv (Windows Update)" -ForegroundColor Gray
    Write-Host "  • BITS (Background Intelligent Transfer)" -ForegroundColor Gray
    Write-Host "  • UsoSvc (Update Orchestrator)" -ForegroundColor Gray
    Write-Host "  • WaaSMedicSvc (WaaS Medic)" -ForegroundColor Gray
    Write-Host "  • DoSvc (Delivery Optimization)" -ForegroundColor Gray
    Write-Host ""
    Write-Host "✅ Drivers: Can still be installed manually" -ForegroundColor Green
    Write-Host "✅ DLLs: NOT touched (repair works)" -ForegroundColor Green
    Write-Host "❌ Security updates: DISABLED!" -ForegroundColor Red
    Write-Host ""
    $confirm = Read-Host "Continue? (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Host "Cancelled by user" -ForegroundColor Yellow
        return
    }
    Write-Host ""
    Write-Host "Disabling Windows Update services..." -ForegroundColor Cyan
    $services = @("wuauserv", "BITS", "UsoSvc", "WaaSMedicSvc", "DoSvc")
    # MUST run as SYSTEM (registry: HKLM:\SYSTEM\CurrentControlSet\Services)
    Invoke-AsSystem -ScriptBlock {
        param($ServiceList)
        foreach ($service in $ServiceList) {
            try {
                Write-Host "  -> [SYSTEM] Processing: $service" -ForegroundColor Gray
                $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
                if ($svc) {
                    # Stop service first
                    if ($svc.Status -ne 'Stopped') {
                        Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
                        Write-Host "     Stopped: $service" -ForegroundColor Yellow
                    }
                    # Disable in registry (Start=4)
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$service" `
                        -Name "Start" -Value 4 -Type DWord -Force -ErrorAction Stop
                    # Clear FailureActions (prevent auto-restart)
                    try {
                        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$service" `
                            -Name "FailureActions" -Type Binary -Value ([byte[]]@()) -Force -ErrorAction SilentlyContinue
                    }
                    catch {
                        # FailureActions might not exist, ignore
                    }
                    Write-Host "     Disabled: $service (Start=4)" -ForegroundColor Green
                }
                else {
                    Write-Host "     Service not found: $service" -ForegroundColor Gray
                }
            }
            catch {
                Write-Warning "  -> [SYSTEM] Failed to disable $service : $($_.Exception.Message)"
            }
        }
    } -ArgumentList $services
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  ✅ WINDOWS UPDATE SERVICES DISABLED!" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "Status:" -ForegroundColor Cyan
    Write-Host "  ❌ Windows Update: DISABLED (services stopped)" -ForegroundColor Red
    Write-Host "  ✅ Driver installation: Works manually from Device Manager" -ForegroundColor Green
    Write-Host "  ✅ Repair possible: Use [5] Repair & Reset if needed" -ForegroundColor Green
    Write-Host ""
    Write-Host "⚠️  To restore: Use [2] Default Settings or call Invoke-WPFUpdatesenableServices" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to continue"
}
function Invoke-WPFUpdatesenableServices {
    <#
    .SYNOPSIS
        Re-enables Windows Update services (restore from [2.1])
    .DESCRIPTION
        **RESTORE FUNCTION for [2.1]**
        Restores the 5 Windows Update services to their default state:
        - wuauserv → Automatic (Start=2)
        - BITS → Automatic (Start=2)
        - UsoSvc → Automatic (Start=2)
        - WaaSMedicSvc → Manual (Start=3)
        - DoSvc → Automatic (Start=2)
        Also starts the services and resets FailureActions to defaults.
    .NOTES
        Reference: KRAKE-FIX-v1.ps1 lines 13024-13032
        Privilege: SYSTEM (required for service registry manipulation)
    #>
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  🔄 RESTORE WINDOWS UPDATE SERVICES" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Restoring Windows Update services to defaults..." -ForegroundColor Yellow
    # MUST run as SYSTEM (registry: HKLM:\SYSTEM\CurrentControlSet\Services)
    Invoke-AsSystem -ScriptBlock {
        $serviceConfigs = @(
            @{Name = "wuauserv"; StartType = 2; StartTypeName = "Automatic" },
            @{Name = "BITS"; StartType = 2; StartTypeName = "Automatic" },
            @{Name = "UsoSvc"; StartType = 2; StartTypeName = "Automatic" },
            @{Name = "WaaSMedicSvc"; StartType = 3; StartTypeName = "Manual" },
            @{Name = "DoSvc"; StartType = 2; StartTypeName = "Automatic" }
        )
        foreach ($config in $serviceConfigs) {
            try {
                Write-Host "  -> [SYSTEM] Restoring: $($config.Name)" -ForegroundColor Gray
                $svc = Get-Service -Name $config.Name -ErrorAction SilentlyContinue
                if ($svc) {
                    # Enable in registry
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($config.Name)" `
                        -Name "Start" -Value $config.StartType -Type DWord -Force -ErrorAction Stop
                    # Reset FailureActions to default (restart after 60s, 3 times)
                    try {
                        $failureActions = [byte[]](0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x60, 0xEA, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x60, 0xEA, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x60, 0xEA, 0x00, 0x00)
                        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($config.Name)" `
                            -Name "FailureActions" -Type Binary -Value $failureActions -Force -ErrorAction SilentlyContinue
                    }
                    catch {
                        # FailureActions might not be supported, ignore
                    }
                    Write-Host "     Enabled: $($config.Name) ($($config.StartTypeName))" -ForegroundColor Green
                    # Start service if it should be automatic
                    if ($config.StartType -eq 2) {
                        Start-Service -Name $config.Name -ErrorAction SilentlyContinue
                        Start-Sleep -Milliseconds 500
                        $svcStatus = (Get-Service -Name $config.Name).Status
                        if ($svcStatus -eq 'Running') {
                            Write-Host "     Started: $($config.Name)" -ForegroundColor Green
                        }
                        else {
                            Write-Host "     Status: $($config.Name) = $svcStatus" -ForegroundColor Yellow
                        }
                    }
                }
                else {
                    Write-Host "     Service not found: $($config.Name)" -ForegroundColor Gray
                }
            }
            catch {
                Write-Warning "  -> [SYSTEM] Failed to restore $($config.Name) : $($_.Exception.Message)"
            }
        }
    }
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  ✅ WINDOWS UPDATE SERVICES RESTORED!" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "Status:" -ForegroundColor Cyan
    Write-Host "  ✅ Windows Update: ENABLED (services running)" -ForegroundColor Green
    Write-Host "  ✅ Security updates: Will be downloaded automatically" -ForegroundColor Green
    Write-Host ""
    Write-Host "Note: It may take a few minutes for Windows Update to start checking." -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to continue"
}
function Invoke-WPFUpdatesdisableDrivers {
    <#
    .SYNOPSIS
        Disables ONLY Windows Update driver installation (leaves services enabled)
    .DESCRIPTION
        **GRANULAR CONTROL - Option [2.2] from v1 Security Hazard Menu**
        Disables ONLY automatic driver installation via Windows Update:
        - SearchOrderConfig = 0 (disable driver search)
        - PreventDeviceMetadataFromNetwork = 1 (block metadata download)
        - ExcludeWUDriversInQualityUpdate = 1 (exclude drivers from updates)
        **DIFFERENCE vs. Security Updates [1]:**
        - Services: ✅ Keep running (security updates still work!)
        - Drivers: ❌ Won't install automatically
        - Restart: ✅ NOT disabled
        - Defer: ✅ NOT configured
        **DIFFERENCE vs. Full Disable WU:**
        - Services: ✅ Keep running
        - Drivers: ❌ Won't install automatically
        - Security updates: ✅ WILL still be downloaded!
        **USE CASE:**
        User wants security updates but NOT automatic driver updates
        (e.g., wants to install drivers manually or use vendor-specific tools).
    .NOTES
        Reference: KRAKE-FIX-v1.ps1 lines 13036-13049
        Privilege: Admin (registry under HKLM:\SOFTWARE\...)
        ℹ️ This is LESS aggressive than [1] Security Updates!
    #>
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host "  ⚠️ DISABLE WINDOWS UPDATE DRIVERS ONLY" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "This will disable automatic driver installation:" -ForegroundColor White
    Write-Host "  • SearchOrderConfig = 0 (disable driver search)" -ForegroundColor Gray
    Write-Host "  • PreventDeviceMetadataFromNetwork = 1" -ForegroundColor Gray
    Write-Host "  • ExcludeWUDriversInQualityUpdate = 1" -ForegroundColor Gray
    Write-Host ""
    Write-Host "✅ Services: Keep running (security updates work!)" -ForegroundColor Green
    Write-Host "✅ Security updates: Will be downloaded" -ForegroundColor Green
    Write-Host "❌ Drivers: Won't install automatically" -ForegroundColor Red
    Write-Host ""
    $confirm = Read-Host "Continue? (Y/N)"
    if ($confirm -ne 'Y' -and $confirm -ne 'y') {
        Write-Host "Cancelled by user" -ForegroundColor Yellow
        return
    }
    Write-Host ""
    Write-Host "Disabling Windows Update driver installation..." -ForegroundColor Cyan
    try {
        # Registry operations (Admin privilege is sufficient)
        # 1. SearchOrderConfig = 0
        if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching")) {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" `
            -Name "SearchOrderConfig" -Value 0 -Type DWord -Force -ErrorAction Stop
        Write-Host "  ✅ SearchOrderConfig = 0" -ForegroundColor Green
        # 2. PreventDeviceMetadataFromNetwork = 1
        if (-not (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata")) {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" `
            -Name "PreventDeviceMetadataFromNetwork" -Value 1 -Type DWord -Force -ErrorAction Stop
        Write-Host "  ✅ PreventDeviceMetadataFromNetwork = 1" -ForegroundColor Green
        # 3. ExcludeWUDriversInQualityUpdate = 1
        if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
            -Name "ExcludeWUDriversInQualityUpdate" -Value 1 -Type DWord -Force -ErrorAction Stop
        Write-Host "  ✅ ExcludeWUDriversInQualityUpdate = 1" -ForegroundColor Green
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host "  ✅ WINDOWS UPDATE DRIVERS DISABLED!" -ForegroundColor Green
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
        Write-Host "Status:" -ForegroundColor Cyan
        Write-Host "  ✅ Windows Update services: RUNNING" -ForegroundColor Green
        Write-Host "  ✅ Security updates: Will be downloaded" -ForegroundColor Green
        Write-Host "  ❌ Driver installation: DISABLED (manual only)" -ForegroundColor Red
        Write-Host ""
        Write-Host "ℹ️  You can still install drivers manually from:" -ForegroundColor Cyan
        Write-Host "   • Device Manager → Update driver → Browse my computer" -ForegroundColor Gray
        Write-Host "   • Vendor-specific driver installers (NVIDIA, AMD, Intel)" -ForegroundColor Gray
        Write-Host ""
        Write-Host "⚠️  To restore: Use [2] Default Settings or call Invoke-WPFUpdatesenableDrivers" -ForegroundColor Yellow
    }
    catch {
        Write-Host ""
        Write-Host "❌ ERROR: Failed to disable driver installation" -ForegroundColor Red
        Write-Host "   $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
    Read-Host "Press Enter to continue"
}
function Invoke-WPFUpdatesenableDrivers {
    <#
    .SYNOPSIS
        Re-enables Windows Update driver installation (restore from [2.2])
    .DESCRIPTION
        **RESTORE FUNCTION for [2.2]**
        Restores automatic driver installation via Windows Update:
        - SearchOrderConfig = 1 (enable driver search)
        - PreventDeviceMetadataFromNetwork → REMOVED
        - ExcludeWUDriversInQualityUpdate → REMOVED
    .NOTES
        Reference: KRAKE-FIX-v1.ps1 lines 13045-13049
        Privilege: Admin (registry under HKLM:\SOFTWARE\...)
    #>
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  🔄 RESTORE WINDOWS UPDATE DRIVER INSTALLATION" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Restoring automatic driver installation..." -ForegroundColor Yellow
    try {
        # 1. SearchOrderConfig = 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" `
            -Name "SearchOrderConfig" -Value 1 -Type DWord -Force -ErrorAction Stop
        Write-Host "  ✅ SearchOrderConfig = 1 (enabled)" -ForegroundColor Green
        # 2. Remove PreventDeviceMetadataFromNetwork
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" `
            -Name "PreventDeviceMetadataFromNetwork" -Force -ErrorAction SilentlyContinue
        Write-Host "  ✅ PreventDeviceMetadataFromNetwork removed" -ForegroundColor Green
        # 3. Remove ExcludeWUDriversInQualityUpdate
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" `
            -Name "ExcludeWUDriversInQualityUpdate" -Force -ErrorAction SilentlyContinue
        Write-Host "  ✅ ExcludeWUDriversInQualityUpdate removed" -ForegroundColor Green
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host "  ✅ WINDOWS UPDATE DRIVER INSTALLATION RESTORED!" -ForegroundColor Green
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""
        Write-Host "Status:" -ForegroundColor Cyan
        Write-Host "  ✅ Driver installation: ENABLED (automatic)" -ForegroundColor Green
        Write-Host "  ✅ Drivers will be downloaded via Windows Update" -ForegroundColor Green
        Write-Host ""
        Write-Host "Note: New drivers may be installed after next Windows Update check." -ForegroundColor Yellow
    }
    catch {
        Write-Host ""
        Write-Host "❌ ERROR: Failed to restore driver installation" -ForegroundColor Red
        Write-Host "   $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
    Read-Host "Press Enter to continue"
}
# ===========================================================
# MODULE ENTRY POINT
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
    Show-WindowsUpdateMenu
}
# ===========================================================
# MODULE EXPORTS
# ===========================================================
Export-ModuleMember -Function @(
    'Show-WindowsUpdateMenu',
    'Invoke-WPFUpdatessecurity',
    'Invoke-WPFUpdatesdefault',
    'Invoke-WPFUpdatesdisable',
    'Invoke-WPFUpdatesdisableServices',
    'Invoke-WPFUpdatesenableServices',
    'Invoke-WPFUpdatesdisableDrivers',
    'Invoke-WPFUpdatesenableDrivers',
    'Invoke-WPFFixesUpdate',
    'Set-WinUtilTaskbaritem',
    'Invoke-WPFSystemRepair',
    'Invoke-ModuleEntry'
)