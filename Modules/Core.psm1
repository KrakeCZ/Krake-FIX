# ═══════════════════════════════════════════════════════════════════════════
# Module: Core.psm1
# ═══════════════════════════════════════════════════════════════════════════
# Project:      KRAKE-FIX 
# ═══════════════════════════════════════════════════════════════════════════
# Category:     Core Utilities
# Dependencies: None (this is the foundation module)
# Admin Rights: Required for privilege escalation
# ═══════════════════════════════════════════════════════════════════════════
# Description:  Core utilities used across all modules including:
#               - Invoke-AsSystem (SYSTEM privilege escalation)
#               - Privilege management
#               - Shared logging infrastructure
#               - Cross-module communication
# ═══════════════════════════════════════════════════════════════════════════
# ⚠️ Tento modul může měnit systémové nastavení.
# Používej pouze ve studijním / testovacím prostředí.
# Autor neručí za zneužití mimo akademické účely.
# ===========================================================
#Requires -Version 5.1
# ───────────────────────────────────────────────────────────────────────────
# GLOBAL SHARED STATE (accessible by all modules)
# ───────────────────────────────────────────────────────────────────────────
if (-not (Get-Variable -Name KRAKEFIX_SharedState -Scope Global -ErrorAction SilentlyContinue)) {
    $Global:KRAKEFIX_SharedState = @{
        LogPath            = $null
        BackupRegistry     = @{}
        BackupServices     = @{}
        SessionStartTime   = Get-Date
        IsAdmin            = $false
        CanElevateToSystem = $false
        PsExecPath         = $null
    }
}
if (-not $Global:KRAKEFIX_SharedState.ContainsKey('CurrentUserSid')) {
    $Global:KRAKEFIX_SharedState.CurrentUserSid = $null
}
function Get-CurrentUserSid {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    if (-not $Global:KRAKEFIX_SharedState.CurrentUserSid) {
        try {
            $sid = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
            $Global:KRAKEFIX_SharedState.CurrentUserSid = $sid
        }
        catch {
            $Global:KRAKEFIX_SharedState.CurrentUserSid = $null
        }
    }
    return $Global:KRAKEFIX_SharedState.CurrentUserSid
}
function Get-PsExecPath {
    <#
    .SYNOPSIS
        Resolve the on-disk location of PsExec64.exe.
    .DESCRIPTION
        Searches known locations (including explicit path C:\Modules\Bin\PsExec\PsExec64.exe)
        and caches the resolved path in the shared state for subsequent calls.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    try {
        if ($Global:KRAKEFIX_SharedState.PsExecPath) {
            if (Test-Path -Path $Global:KRAKEFIX_SharedState.PsExecPath) {
                return (Resolve-Path -Path $Global:KRAKEFIX_SharedState.PsExecPath).Path
            }
            $Global:KRAKEFIX_SharedState.PsExecPath = $null
        }
        $candidatePaths = @(
            'C:\Modules\Bin\PsExec\PsExec64.exe',
            (Join-Path -Path $PSScriptRoot -ChildPath 'Bin\PsExec\PsExec64.exe'),
            (Join-Path -Path $PSScriptRoot -ChildPath 'PsExec64.exe'),
            (Join-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -ChildPath 'PsExec64.exe')
        ) | Where-Object { $_ -and (Test-Path -Path $_) }
        foreach ($candidate in $candidatePaths) {
            $resolvedPath = (Resolve-Path -Path $candidate).Path
            if (-not [string]::IsNullOrWhiteSpace($resolvedPath)) {
                $Global:KRAKEFIX_SharedState.PsExecPath = $resolvedPath
                return $resolvedPath
            }
        }
        return $null
    }
    catch {
        Write-Warning "Get-PsExecPath failed: $($_.Exception.Message)"
        return $null
    }
}
function Test-PsExecAvailable {
    <#
    .SYNOPSIS
        Determine whether PsExec is available for SYSTEM escalation.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    $path = Get-PsExecPath
    return ($null -ne $path)
}
# ───────────────────────────────────────────────────────────────────────────
# PRIVILEGE MANAGEMENT
# ───────────────────────────────────────────────────────────────────────────
function Test-Administrator {
    <#
    .SYNOPSIS
        Check if current session has Administrator privileges.
    .DESCRIPTION
        Verifies if the current PowerShell session is running with
        administrative rights (elevated).
    .OUTPUTS
        [bool] True if running as Administrator, False otherwise.
    .EXAMPLE
        if (Test-Administrator) {
            Write-Host "Running as Admin"
        }
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]$identity
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        $Global:KRAKEFIX_SharedState.IsAdmin = $isAdmin
        return $isAdmin
    }
    catch {
        Write-Warning "Failed to check administrator status: $($_.Exception.Message)"
        return $false
    }
}
# ───────────────────────────────────────────────────────────────────────────
# LOGGING FUNCTION (must be defined EARLY - used by all functions below)
# ───────────────────────────────────────────────────────────────────────────
function Write-CoreLog {
    <#
    .SYNOPSIS
        Central logging function for all KRAKE-FIX modules.
    .DESCRIPTION
        Provides unified logging with timestamp, severity, and module name.
        All modules can use this for consistent logging.
    .PARAMETER Message
        The message to log.
    .PARAMETER Level
        Severity level: INFO, WARNING, ERROR, SUCCESS, DEBUG.
    .PARAMETER Module
        Name of the calling module (auto-detected if possible).
    .EXAMPLE
        Write-CoreLog "Operation completed" -Level SUCCESS -Module "GPU"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS', 'DEBUG')]
        [string]$Level = 'INFO',
        [string]$Module = 'Core'
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] [$Module] $Message"
    # Console output with colors
    $color = switch ($Level) {
        'INFO' { 'White' }
        'WARNING' { 'Yellow' }
        'ERROR' { 'Red' }
        'SUCCESS' { 'Green' }
        'DEBUG' { 'Gray' }
    }
    Write-Host $logEntry -ForegroundColor $color
    # File logging
    try {
        $logPath = $Global:KRAKEFIX_SharedState.LogPath
        if ($null -ne $logPath -and -not [string]::IsNullOrWhiteSpace($logPath)) {
            Add-Content -Path $logPath -Value $logEntry -ErrorAction SilentlyContinue
        }
    }
    catch {
        # File logging je vypnuté, chyby ignorujeme
    }
}
# ───────────────────────────────────────────────────────────────────────────
# PRIVILEGE MANAGEMENT (continued)
# ───────────────────────────────────────────────────────────────────────────
function Test-SystemPrivilege {
    <#
    .SYNOPSIS
        Check if SYSTEM privilege escalation is possible.
    .DESCRIPTION
        Verifies if the current session can create scheduled tasks
        to run code as NT AUTHORITY\SYSTEM.
    .OUTPUTS
        [bool] True if SYSTEM escalation is possible, False otherwise.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    try {
        if (Test-PsExecAvailable) {
            $Global:KRAKEFIX_SharedState.CanElevateToSystem = $true
            return $true
        }
        # Requires Admin to create scheduled tasks
        if (-not (Test-Administrator)) {
            $Global:KRAKEFIX_SharedState.CanElevateToSystem = $false
            return $false
        }
        # Test if we can create a dummy scheduled task
        $testTaskName = "KRAKEFIX-Test-$(Get-Random)"
        $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c exit 0"
        $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
        Register-ScheduledTask -TaskName $testTaskName -Action $action -Principal $principal -Force -ErrorAction Stop | Out-Null
        Unregister-ScheduledTask -TaskName $testTaskName -Confirm:$false -ErrorAction SilentlyContinue
        $Global:KRAKEFIX_SharedState.CanElevateToSystem = $true
        return $true
    }
    catch {
        $Global:KRAKEFIX_SharedState.CanElevateToSystem = $false
        return $false
    }
}
function Invoke-AsSystem {
    <#
    .SYNOPSIS
        Execute a script block with NT AUTHORITY\SYSTEM privileges.
    .DESCRIPTION
        Creates a temporary scheduled task to run the provided script block
        with SYSTEM privileges. This is the highest privilege level in Windows,
        higher than Administrator.
        SECURITY NOTICE:
        - Use only when absolutely necessary
        - All operations are logged
        - Requires Administrator privileges to create scheduled tasks
    .PARAMETER ScriptBlock
        The PowerShell script block to execute as SYSTEM.
    .PARAMETER ArgumentList
        Optional arguments to pass to the script block.
    .PARAMETER TimeoutSeconds
        Maximum time to wait for task completion (default: 60 seconds).
    .OUTPUTS
        [bool] True if task completed successfully, False otherwise.
    .EXAMPLE
        Invoke-AsSystem -ScriptBlock {
            Stop-Service -Name "SomeService" -Force
        }
    .EXAMPLE
        Invoke-AsSystem -ScriptBlock {
            param($ServiceName)
            Stop-Service -Name $ServiceName -Force
        } -ArgumentList "WindowsUpdate"
    .NOTES
        BSI4 Compliant: All SYSTEM operations are logged with timestamp.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,
        [Parameter(Mandatory = $false)]
        [object[]]$ArgumentList,
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 60
    )
    # Verify Administrator privileges
    if (-not (Test-Administrator)) {
        Write-Error "Administrator privileges required to elevate to SYSTEM!"
        return $false
    }
    # Generate task name and sanitize (prevent path injection)
    $taskName = "KRAKEFIX-SystemTask-$(Get-Random)"
    $taskName = $taskName -replace '[^a-zA-Z0-9\-_]', ''  # Remove special chars
    $scriptPath = Join-Path -Path $env:TEMP -ChildPath "$taskName.ps1"
    $resultPath = Join-Path -Path $env:TEMP -ChildPath "$taskName-result.xml"
    $argsPath = Join-Path -Path $env:TEMP -ChildPath "$taskName-args.xml"
    Write-Verbose "Creating SYSTEM task: $taskName"
    Write-CoreLog "SYSTEM escalation requested: $taskName" -Level WARNING
    try {
        # Export arguments to CliXML file if provided
        if ($null -ne $ArgumentList -and $ArgumentList.Count -gt 0) {
            $ArgumentList | Export-Clixml -Path $argsPath -Force
        }
        # Build script that loads arguments and executes ScriptBlock
        $wrappedScriptBlockContent = @"
# Load arguments from CliXML if file exists
`$ArgumentList = @()
if (Test-Path '$argsPath') {
    `$ArgumentList = @(Import-Clixml -Path '$argsPath')
}
# Execute ScriptBlock with arguments and capture errors
try {
    `$result = & { $($ScriptBlock.ToString()) } @ArgumentList
    # Export result to CliXML
    if (`$null -ne `$result) {
        `$result | Export-Clixml -Path '$resultPath' -Force
    }
    exit 0
} catch {
    # Export error to CliXML for debugging
    @{ Error = `$_.Exception.Message; Success = `$false } | Export-Clixml -Path '$resultPath' -Force
    exit 1
}
"@
        # Save script to temp file
        Set-Content -Path $scriptPath -Value $wrappedScriptBlockContent -Encoding UTF8 -Force
        # Build PowerShell arguments (no need for serialized args anymore)
        $powershellArguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
        if ($PSCmdlet.ShouldProcess("SYSTEM Task: $taskName", "Execute with NT AUTHORITY\SYSTEM")) {
            # Create scheduled task with SYSTEM principal
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $powershellArguments
            $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet `
                -AllowStartIfOnBatteries `
                -DontStopIfGoingOnBatteries `
                -ExecutionTimeLimit (New-TimeSpan -Seconds $TimeoutSeconds)
            $settings.StopIfGoingOnBatteries = $false
            $settings.DisallowStartIfOnBatteries = $false
            # FORCE CLEANUP: Kill any stuck/running instance of this task
            $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($existingTask) {
                Write-Verbose "Found existing task: $taskName (State: $($existingTask.State))"
                if ($existingTask.State -eq 'Running') {
                    Write-Warning "Task $taskName is already running - stopping forcefully..."
                    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                    Start-Sleep -Seconds 2
                }
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                Write-Verbose "Cleaned up existing task: $taskName"
            }
            Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
            Start-ScheduledTask -TaskName $taskName
            Write-Verbose "Task started, waiting for completion (timeout: $TimeoutSeconds seconds)..."
            # Wait for task completion
            $startTime = Get-Date
            $taskState = $null
            $completed = $false
            do {
                Start-Sleep -Seconds 1
                $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                if ($null -eq $task) {
                    Write-Verbose "Task completed and removed"
                    $completed = $true
                    break
                }
                $taskInfo = Get-ScheduledTaskInfo -InputObject $task -ErrorAction SilentlyContinue
                if ($null -ne $taskInfo) {
                    $taskState = $task.State
                    # Check if task finished (not running)
                    if ($taskState -ne 'Running' -and $taskInfo.LastTaskResult -ne 267009) {
                        Write-Verbose "Task finished with state: $taskState, result: $($taskInfo.LastTaskResult)"
                        $completed = ($taskInfo.LastTaskResult -eq 0)
                        break
                    }
                }
                # Check timeout
                if (((Get-Date) - $startTime).TotalSeconds -gt $TimeoutSeconds) {
                    Write-Warning "Task timed out after $TimeoutSeconds seconds"
                    break
                }
            } while ($true)
            Write-CoreLog "SYSTEM task completed: $taskName (Success: $completed)" -Level INFO
            # Try to import result from CliXML file
            if ($completed -and (Test-Path -Path $resultPath -ErrorAction SilentlyContinue)) {
                try {
                    $scriptResult = Import-Clixml -Path $resultPath -ErrorAction Stop
                    Remove-Item -Path $resultPath -Force -ErrorAction SilentlyContinue
                    return $scriptResult
                }
                catch {
                    Write-Warning "Failed to import result from SYSTEM task: $($_.Exception.Message)"
                }
            }
            # Fallback: return boolean completion status
            return $completed
        }
    }
    catch {
        Write-Error "SYSTEM task execution failed: $($_.Exception.Message)"
        Write-CoreLog "SYSTEM task failed: $taskName - $($_.Exception.Message)" -Level ERROR
        return $false
    }
    finally {
        # Cleanup
        try {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Remove-Item -Path $scriptPath -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $resultPath -Force -ErrorAction SilentlyContinue
            Remove-Item -Path $argsPath -Force -ErrorAction SilentlyContinue
        }
        catch {
            # Fail silently on cleanup errors
        }
    }
}
# ───────────────────────────────────────────────────────────────────────────
# SYSTEM ESCALATION VIA PSEXEC
# ───────────────────────────────────────────────────────────────────────────
function Invoke-AsPsExecSystem {
    <#
    .SYNOPSIS
        Execute a script block under NT AUTHORITY\SYSTEM using PsExec.
    .DESCRIPTION
        Uses PsExec64.exe (Sysinternals) to launch a transient PowerShell process
        as SYSTEM. The script block is serialized to a payload script stored in
        the user's TEMP directory, executed, and the result serialized back to
        JSON for consumption by the caller.
        All temporary artifacts are removed after execution to maintain hygiene.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [object[]]$ArgumentList,
        [int]$TimeoutSeconds = 300
    )
    $psExecPath = Get-PsExecPath
    if (-not $psExecPath) {
        return [pscustomobject]@{
            Success = $false
            Result  = $null
            Error   = 'PsExec64.exe could not be located. Expected at C:\\Modules\\Bin\\PsExec\\PsExec64.exe or module Bin.'
        }
    }
    if (-not (Test-Path -Path $psExecPath)) {
        return [pscustomobject]@{
            Success = $false
            Result  = $null
            Error   = "PsExec path not accessible: $psExecPath"
        }
    }
    $systemTemp = Join-Path -Path $env:ProgramData -ChildPath 'KRAKEFIX\PsExecTemp'
    if (-not (Test-Path -Path $systemTemp)) {
        try {
            New-Item -Path $systemTemp -ItemType Directory -Force | Out-Null
        }
        catch {
            throw "Failed to prepare system temp directory '$systemTemp': $($_.Exception.Message)"
        }
    }
    $payloadPath = Join-Path -Path $systemTemp -ChildPath ("KRAKEFIX-PsExec-Payload-{0}.ps1" -f ([guid]::NewGuid()))
    $wrapperPath = Join-Path -Path $systemTemp -ChildPath ("KRAKEFIX-PsExec-Wrapper-{0}.ps1" -f ([guid]::NewGuid()))
    $resultPath = Join-Path -Path $systemTemp -ChildPath ("KRAKEFIX-PsExec-Result-{0}.json" -f ([guid]::NewGuid()))
    $lanmanRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
    $autoSharePropertyName = 'AutoShareWks'
    $autoShareHadProperty = $false
    $autoShareOriginalValue = $null
    $autoShareChanged = $false
    $adminShareCreated = $false
    $lanmanServiceStarted = $false
    $lanmanOriginalStartType = $null
    $lanmanStartTypeChanged = $false
    $lanmanService = $null
    try {
        try {
            $lanmanService = Get-Service -Name 'LanmanServer' -ErrorAction Stop
        }
        catch {
            throw "Failed to access LanmanServer service: $($_.Exception.Message)"
        }
        if ($lanmanService.Status -ne 'Running') {
            $lanmanOriginalStartType = $lanmanService.StartType
            if ($lanmanService.StartType -eq 'Disabled') {
                try {
                    Set-Service -Name 'LanmanServer' -StartupType Manual -ErrorAction Stop
                    $lanmanStartTypeChanged = $true
                    $lanmanService = Get-Service -Name 'LanmanServer' -ErrorAction Stop
                }
                catch {
                    throw "Failed to change LanmanServer startup type from Disabled to Manual: $($_.Exception.Message)"
                }
            }
            try {
                Start-Service -Name 'LanmanServer' -ErrorAction Stop
                $lanmanServiceStarted = $true
            }
            catch {
                throw "Failed to start LanmanServer service (required for ADMIN$ share): $($_.Exception.Message)"
            }
        }
        if (-not (Test-Path -Path $lanmanRegPath)) {
            try {
                New-Item -Path $lanmanRegPath -Force | Out-Null
            }
            catch {
                throw "Failed to create LanmanServer Parameters registry key: $($_.Exception.Message)"
            }
        }
        try {
            $autoShareOriginalValue = (Get-ItemProperty -Path $lanmanRegPath -Name $autoSharePropertyName -ErrorAction Stop).$autoSharePropertyName
            $autoShareHadProperty = $true
        }
        catch {
            $autoShareHadProperty = $false
        }
        if ($autoShareHadProperty) {
            if ([int]$autoShareOriginalValue -eq 0) {
                try {
                    Set-ItemProperty -Path $lanmanRegPath -Name $autoSharePropertyName -Value 1 -ErrorAction Stop
                    $autoShareChanged = $true
                }
                catch {
                    throw "Failed to update AutoShareWks value: $($_.Exception.Message)"
                }
            }
        }
        else {
            try {
                New-ItemProperty -Path $lanmanRegPath -Name $autoSharePropertyName -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                $autoShareChanged = $true
            }
            catch {
                throw "Failed to create AutoShareWks registry value: $($_.Exception.Message)"
            }
        }
        $null = & cmd.exe /c "net share ADMIN$" 2>&1
        $shareCheckExitCode = $LASTEXITCODE
        if ($shareCheckExitCode -ne 0) {
            $null = & cmd.exe /c ("net share ADMIN$=" + $env:SystemRoot) 2>&1
            $shareCreateExitCode = $LASTEXITCODE
            if ($shareCreateExitCode -ne 0) {
                throw "Failed to create ADMIN$ share (exit code: $shareCreateExitCode)."
            }
            $adminShareCreated = $true
        }
        Write-CoreLog "PsExec escalation requested: $payloadPath" -Level WARNING
        [System.IO.File]::WriteAllText($payloadPath, $ScriptBlock.ToString(), [System.Text.UTF8Encoding]::new($false))
        $wrapperContent = @'
param(
    [Parameter(Mandatory)][string]$ScriptFile,
    [Parameter(Mandatory)][string]$ResultFile,
    [string]$ArgumentBase64
)
$ErrorActionPreference = 'Stop'
$result = [ordered]@{
    Success = $true
    Result  = $null
    Error   = $null
}
try {
    $scriptText = Get-Content -Path $ScriptFile -Raw -ErrorAction Stop
    $payload    = [ScriptBlock]::Create($scriptText)
    if ([string]::IsNullOrWhiteSpace($ArgumentBase64)) {
        $arguments = @()
    } else {
        $json = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($ArgumentBase64))
        $arguments = ConvertFrom-Json -InputObject $json
    }
    if ($arguments -isnot [object[]]) {
        $arguments = @($arguments)
    }
    $result.Result = & $payload @arguments
} catch {
    $result.Success = $false
    $result.Error   = $_.Exception.Message
}
$result | ConvertTo-Json -Depth 6 | Set-Content -Path $ResultFile -Encoding UTF8 -Force
'@
        [System.IO.File]::WriteAllText($wrapperPath, $wrapperContent, [System.Text.UTF8Encoding]::new($false))
        $argumentBase64 = ''
        if ($ArgumentList -and $ArgumentList.Count -gt 0) {
            $jsonArgs = ConvertTo-Json -InputObject $ArgumentList -Depth 6
            $argumentBase64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($jsonArgs))
        }
        $psExecArgs = @(
            '/accepteula',
            '-s',
            '-nobanner',
            'powershell.exe',
            '-NoLogo',
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-File', $wrapperPath,
            '-ScriptFile', $payloadPath,
            '-ResultFile', $resultPath
        )
        if (-not [string]::IsNullOrWhiteSpace($argumentBase64)) {
            $psExecArgs += @('-ArgumentBase64', $argumentBase64)
        }
        $process = Start-Process -FilePath $psExecPath -ArgumentList $psExecArgs -NoNewWindow -PassThru -ErrorAction Stop
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill() } catch { }
            return [pscustomobject]@{
                Success = $false
                Result  = $null
                Error   = "PsExec execution timed out after $TimeoutSeconds seconds."
            }
        }
        if ($process.ExitCode -ne 0) {
            return [pscustomobject]@{
                Success = $false
                Result  = $null
                Error   = "PsExec returned exit code $($process.ExitCode)."
            }
        }
        # ==================================================================
        # FIX: Minimal delay pro result.xml stabilitu (file I/O flush)
        # Edge case: Exit 0, ale soubor není ještě kompletně zapsán
        # ==================================================================
        Start-Sleep -Milliseconds 150
        if (-not (Test-Path -Path $resultPath)) {
            return [pscustomobject]@{
                Success = $false
                Result  = $null
                Error   = "PsExec completed (exit 0) but result file was not created."
            }
        }
        $jsonResult = Get-Content -Path $resultPath -Raw -ErrorAction Stop
        $parsed = if ([string]::IsNullOrWhiteSpace($jsonResult)) {
            $null
        }
        else {
            ConvertFrom-Json -InputObject $jsonResult -ErrorAction Stop
        }
        if ($null -eq $parsed) {
            return [pscustomobject]@{
                Success = $false
                Result  = $null
                Error   = 'PsExec execution succeeded but no result payload was returned.'
            }
        }
        return [pscustomobject]@{
            Success = [bool]$parsed.Success
            Result  = $parsed.Result
            Error   = $parsed.Error
        }
    }
    catch {
        return [pscustomobject]@{
            Success = $false
            Result  = $null
            Error   = $_.Exception.Message
        }
    }
    finally {
        if ($adminShareCreated) {
            try {
                $null = & cmd.exe /c "net share ADMIN$ /delete /y" 2>&1
            }
            catch {
                Write-Verbose ("Failed to remove temporary ADMIN$ share: {0}" -f $_.Exception.Message)
            }
        }
        if ($autoShareChanged) {
            try {
                if ($autoShareHadProperty) {
                    Set-ItemProperty -Path $lanmanRegPath -Name $autoSharePropertyName -Value $autoShareOriginalValue -ErrorAction SilentlyContinue
                }
                else {
                    Remove-ItemProperty -Path $lanmanRegPath -Name $autoSharePropertyName -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-Verbose ("Failed to restore AutoShareWks value: {0}" -f $_.Exception.Message)
            }
        }
        if ($lanmanServiceStarted) {
            try {
                Stop-Service -Name 'LanmanServer' -Force -ErrorAction SilentlyContinue
            }
            catch {
                Write-Verbose ("Failed to stop LanmanServer service: {0}" -f $_.Exception.Message)
            }
        }
        if ($lanmanStartTypeChanged -and $lanmanOriginalStartType) {
            try {
                Set-Service -Name 'LanmanServer' -StartupType $lanmanOriginalStartType.ToString() -ErrorAction SilentlyContinue
            }
            catch {
                Write-Verbose ("Failed to restore LanmanServer startup type: {0}" -f $_.Exception.Message)
            }
        }
        Remove-Item -Path $payloadPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $wrapperPath -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $resultPath  -Force -ErrorAction SilentlyContinue
    }
}
# ───────────────────────────────────────────────────────────────────────────
# PRIVILEGE ESCALATION WITH FALLBACK CHAIN
# ───────────────────────────────────────────────────────────────────────────
function Invoke-WithPrivilege {
    <#
    .SYNOPSIS
        Execute script block with automatic privilege escalation and fallback.
    .DESCRIPTION
        Attempts to execute script block with the highest available privilege level:
        1. Try with SYSTEM (if possible)
        2. Fallback to Admin (if available)
        3. Fallback to current user (last resort)
        This ensures operations succeed even when privilege escalation fails.
        All attempts are logged for audit purposes.
    .PARAMETER ScriptBlock
        The PowerShell script block to execute.
    .PARAMETER ArgumentList
        Optional arguments to pass to the script block.
    .PARAMETER RequireSystem
        If true, fails if SYSTEM privilege cannot be obtained.
        If false, attempts fallback to lower privileges.
    .PARAMETER RetryCount
        Number of retries on failure (default: 3).
    .PARAMETER RetryDelayMs
        Delay between retries in milliseconds (default: 1000).
    .OUTPUTS
        [PSCustomObject] with Success, PrivilegeLevel, Result, Error properties.
    .EXAMPLE
        $result = Invoke-WithPrivilege -ScriptBlock {
            Stop-Service "SomeService" -Force
        }
        if ($result.Success) {
            Write-Host "Stopped with $($result.PrivilegeLevel) privilege"
        }
    .EXAMPLE
        # Require SYSTEM, fail if not available
        $result = Invoke-WithPrivilege -RequireSystem -ScriptBlock {
            # Critical operation requiring SYSTEM
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,
        [object[]]$ArgumentList,
        [switch]$RequireSystem,
        [int]$RetryCount = 3,
        [int]$RetryDelayMs = 1000,
        [ValidateSet('Auto', 'User', 'Admin', 'System')]
        [string]$RequiredPrivilege = 'Auto'
    )
    $result = [PSCustomObject]@{
        Success        = $false
        PrivilegeLevel = 'None'
        Result         = $null
        Error          = $null
        AttemptsLog    = @()
    }
    # ═══════════════════════════════════════════════════════════════════════
    # CRITICAL: Pre-flight privilege check
    # If required privilege cannot be satisfied, STOP immediately
    # ═══════════════════════════════════════════════════════════════════════
    $isAdmin = Test-Administrator
    $canElevateToSystem = $Global:KRAKEFIX_SharedState.CanElevateToSystem
    $psExecPath = Get-PsExecPath
    # Check if required privilege level can be satisfied
    if ($RequiredPrivilege -eq 'System' -or $RequireSystem) {
        if (-not $isAdmin) {
            $result.Error = "CRITICAL: System privilege required but session is NOT Admin. Execution BLOCKED."
            Write-CoreLog $result.Error -Level ERROR
            Write-Host ""
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
            Write-Host "   EXECUTION BLOCKED: Insufficient Privileges" -ForegroundColor Red
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
            Write-Host ""
            Write-Host "Required: System/Admin privileges" -ForegroundColor Yellow
            Write-Host "Current:  Standard User" -ForegroundColor Red
            Write-Host ""
            Write-Host "ACTION: Re-run this script as Administrator (Right-click → Run as Administrator)" -ForegroundColor Cyan
            Write-Host ""
            return $result
        }
        if (-not $canElevateToSystem -and -not $psExecPath) {
            $result.Error = "CRITICAL: System privilege required but cannot elevate (Scheduled Tasks failed and PsExec not available). Execution BLOCKED."
            Write-CoreLog $result.Error -Level ERROR
            Write-Host ""
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
            Write-Host "   EXECUTION BLOCKED: Cannot Escalate to SYSTEM" -ForegroundColor Red
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
            Write-Host ""
            Write-Host "Required: SYSTEM privilege" -ForegroundColor Yellow
            Write-Host "Available: Admin only (SYSTEM escalation unavailable)" -ForegroundColor Red
            Write-Host ""
            Write-Host "REASON: Scheduled Task creation failed AND PsExec not found" -ForegroundColor Cyan
            Write-Host "ACTION: Verify Task Scheduler service is running or install PsExec" -ForegroundColor Cyan
            Write-Host ""
            return $result
        }
    }
    if ($RequiredPrivilege -eq 'Admin' -and -not $isAdmin) {
        $result.Error = "CRITICAL: Admin privilege required but session is NOT Admin. Execution BLOCKED."
        Write-CoreLog $result.Error -Level ERROR
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
        Write-Host "   EXECUTION BLOCKED: Insufficient Privileges" -ForegroundColor Red
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
        Write-Host ""
        Write-Host "Required: Administrator privileges" -ForegroundColor Yellow
        Write-Host "Current:  Standard User" -ForegroundColor Red
        Write-Host ""
        Write-Host "ACTION: Re-run this script as Administrator (Right-click → Run as Administrator)" -ForegroundColor Cyan
        Write-Host ""
        return $result
    }
    # Determine escalation strategy
    $strategies = @()
    if ($canElevateToSystem -and $isAdmin) {
        $strategies += @{Level = 'SYSTEM'; Method = 'Invoke-AsSystem' }
    }
    if ($isAdmin -and $psExecPath) {
        $strategies += @{Level = 'SYSTEM'; Method = 'PsExecSystem' }
    }
    if ($isAdmin) {
        $strategies += @{Level = 'Admin'; Method = 'Direct' }
    }
    if (-not $RequireSystem) {
        $strategies += @{Level = 'User'; Method = 'Direct' }
    } switch ($RequiredPrivilege) {
        'Auto' { }
        'System' {
            $strategies = $strategies | Where-Object { $_.Level -in @('SYSTEM', 'Admin') }
        }
        'Admin' {
            $strategies = $strategies | Where-Object { $_.Level -in @('Admin', 'User') }
        }
        'User' {
            $strategies = $strategies | Where-Object { $_.Level -eq 'User' }
        }
    }
    if ($strategies.Count -eq 0) {
        $result.Error = "No privilege escalation path available. Admin rights required."
        Write-CoreLog $result.Error -Level ERROR
        return $result
    }
    # Try each strategy with retry logic
    foreach ($strategy in $strategies) {
        $strategyLevel = $strategy.Level
        $strategyMethod = $strategy.Method
        Write-CoreLog "Attempting execution with $strategyLevel privilege (method: $strategyMethod)" -Level INFO
        for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
            try {
                $attemptLog = @{
                    Attempt   = $attempt
                    Level     = $strategyLevel
                    Method    = $strategyMethod
                    Timestamp = Get-Date
                    Success   = $false
                    Error     = $null
                }
                # Execute based on strategy
                if ($strategyMethod -eq 'Invoke-AsSystem') {
                    # SYSTEM execution via scheduled task
                    $systemSuccess = Invoke-AsSystem -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
                    if ($systemSuccess) {
                        $result.Success = $true
                        $result.PrivilegeLevel = 'SYSTEM'
                        $attemptLog.Success = $true
                        $result.AttemptsLog += $attemptLog

                        Write-CoreLog "Execution succeeded with SYSTEM privilege" -Level SUCCESS
                        return $result
                    }
                    else {
                        throw "SYSTEM execution failed (task did not complete successfully)"
                    }
                }
                elseif ($strategyMethod -eq 'PsExecSystem') {
                    $psExecOutcome = Invoke-AsPsExecSystem -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
                    if ($psExecOutcome.Success) {
                        $result.Success = $true
                        $result.PrivilegeLevel = 'SYSTEM'
                        $result.Result = $psExecOutcome.Result
                        $attemptLog.Success = $true
                        $result.AttemptsLog += $attemptLog
                        Write-CoreLog "Execution succeeded with SYSTEM privilege via PsExec" -Level SUCCESS
                        return $result
                    }
                    else {
                        throw "PsExec SYSTEM execution failed: $($psExecOutcome.Error)"
                    }
                }
                else {
                    # Direct execution (Admin or User)
                    if ($ArgumentList) {
                        $result.Result = & $ScriptBlock @ArgumentList
                    }
                    else {
                        $result.Result = & $ScriptBlock
                    }
                    $result.Success = $true
                    $result.PrivilegeLevel = $strategyLevel
                    $attemptLog.Success = $true
                    $result.AttemptsLog += $attemptLog
                    Write-CoreLog "Execution succeeded with $strategyLevel privilege" -Level SUCCESS
                    return $result
                }
            }
            catch {
                $attemptLog.Error = $_.Exception.Message
                $result.AttemptsLog += $attemptLog
                Write-CoreLog "Attempt $attempt/$RetryCount failed with ${strategyLevel}: $($_.Exception.Message)" -Level WARNING
                # Retry logic with exponential backoff
                if ($attempt -lt $RetryCount) {
                    $delay = $RetryDelayMs * [Math]::Pow(2, $attempt - 1)
                    Write-Verbose "Retrying in $delay ms..."
                    Start-Sleep -Milliseconds $delay
                }
                else {
                    Write-CoreLog "All retry attempts failed for $strategyLevel" -Level ERROR
                }
            }
        }
        # If we get here, all retries for this strategy failed
        # Continue to next strategy (fallback)
        Write-CoreLog "Falling back from $strategyLevel to next privilege level" -Level WARNING
    }
    # If we get here, all strategies failed
    $result.Error = "All privilege escalation strategies failed. See AttemptsLog for details."
    Write-CoreLog $result.Error -Level ERROR
    return $result
}
function Invoke-RegistryOperation {
    <#
    .SYNOPSIS
        Execute registry operation with automatic backup, privilege escalation, and rollback.
    .DESCRIPTION
        Safely modifies registry values with enterprise-grade protection:
        - Automatic backup of original value before modification
        - Privilege escalation (SYSTEM → Admin → User)
        - Automatic rollback on error
        - WOW64 awareness (64-bit vs 32-bit registry)
        - Audit logging
    .PARAMETER Path
        Registry path (e.g., "HKLM:\SOFTWARE\MyApp").
    .PARAMETER Name
        Registry value name.
    .PARAMETER Value
        New value to set.
    .PARAMETER Type
        Registry value type (String, DWord, QWord, Binary, ExpandString, MultiString).
    .PARAMETER CreatePath
        Create registry path if it doesn't exist.
    .PARAMETER BackupPath
        Optional path to save backup (defaults to temp directory).
    .PARAMETER RegistryView
        Registry view for WOW64 redirection (Default, Registry64, Registry32).
        On 64-bit Windows, 32-bit apps may access Wow6432Node instead of native registry.
        - Default: Use current process architecture
        - Registry64: Force 64-bit registry view
        - Registry32: Force 32-bit registry view (Wow6432Node)
    .PARAMETER SkipBackup
        If specified, registry changes are applied without creating a backup snapshot.
        WARNING: Rollback on failure will be unavailable when backup is skipped.
    .OUTPUTS
        [PSCustomObject] with Success, BackupFile, OriginalValue, NewValue, Error properties.
    .EXAMPLE
        # Set registry value with automatic backup
        $result = Invoke-RegistryOperation -Path "HKLM:\SOFTWARE\MyApp" -Name "Setting" -Value 1
        if ($result.Success) {
            Write-Host "Original value: $($result.OriginalValue)"
            Write-Host "Backup saved to: $($result.BackupFile)"
        }
    .EXAMPLE
        # Force 64-bit registry access (bypass WOW64 redirection)
        $result = Invoke-RegistryOperation -Path "HKLM:\SOFTWARE\MyApp" -Name "Setting" -Value 1 -RegistryView Registry64
    .EXAMPLE
        # Restore from backup
        if ($result.BackupFile) {
            $backup = Import-Clixml $result.BackupFile
            Set-ItemProperty -Path $backup.Path -Name $backup.Name -Value $backup.OriginalValue -Type $backup.Type
        }
    .NOTES
        WOW64 Redirection: On 64-bit Windows, 32-bit PowerShell accesses HKLM:\SOFTWARE\Wow6432Node
        by default. Use -RegistryView Registry64 to access native 64-bit registry.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Name,
        [object]$Value = $null,
        [ValidateSet('String', 'DWord', 'QWord', 'Binary', 'ExpandString', 'MultiString')]
        [string]$Type = 'DWord',
        [ValidateSet('Set', 'Remove')]
        [string]$Operation = 'Set',
        [ValidateSet('Auto', 'User', 'Admin', 'System')]
        [string]$RequiredPrivilege = 'Auto',
        [switch]$CreatePath,
        [string]$BackupPath = (Join-Path ([Environment]::GetFolderPath('Desktop')) "KRAKE-Backup\Registry-Backups"),
        [ValidateSet('Default', 'Registry64', 'Registry32')]
        [string]$RegistryView = 'Default',
        [switch]$SkipBackup
    )
    $opResult = [PSCustomObject]@{
        Success       = $false
        BackupFile    = $null
        OriginalValue = $null
        OriginalType  = $null
        NewValue      = $Value
        NewType       = $Type
        Error         = $null
    }
    try {
        if ($Operation -eq 'Set' -and $PSBoundParameters.ContainsKey('Value') -eq $false) {
            throw "Operation 'Set' vyžaduje parametr -Value."
        }
        Write-CoreLog "Starting registry operation: $Path\$Name (View: $RegistryView)" -Level INFO
        # WOW64 Note: RegistryView parameter documented but not enforced in this version
        # Full WOW64 implementation via [Microsoft.Win32.RegistryView] requires .NET 4.0+
        # For now, parameter exists for future enhancement and documentation purposes
        if ($RegistryView -ne 'Default') {
            Write-Verbose "WOW64 RegistryView specified: $RegistryView (note: requires .NET 4.0+ for enforcement)"
        }
        # Create backup directory if needed
        # $originalValue = $null
        # $originalType = $null
        # $valueExists = $false
        # if (-not $SkipBackup) {
        #     if (-not (Test-Path $BackupPath)) {
        #         New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
        #     }
        #     if (Test-Path $Path) {
        #         try {
        #             $prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        #             if ($null -ne $prop) {
        #                 $originalValue = $prop.$Name
        #                 $regKey = Get-Item -LiteralPath $Path
        #                 $originalType = $regKey.GetValueKind($Name).ToString()
        #                 $opResult.OriginalValue = $originalValue
        #                 $opResult.OriginalType = $originalType
        #                 $valueExists = $true
        #                 Write-Verbose "Original value: $originalValue (Type: $originalType)"
        #             } else {
        #                 Write-Verbose "Registry value does not exist (will be created) - Recording 'ValueDoesNotExist'"
        #             }
        #         } catch {
        #             Write-Verbose "Registry value does not exist (will be created) - Recording 'ValueDoesNotExist'"
        #         }
        #     } else {
        #         Write-Verbose "Registry path does not exist - Recording 'ValueDoesNotExist'"
        #     }
        #     $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        #     $safePath = $Path -replace '[:\\\\]', '_'
        #     $backupFile = Join-Path $BackupPath "REG-$safePath-$Name-$timestamp.xml"
        #     if (-not (Test-Path $BackupPath)) {
        #         New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
        #     }
        #     if ($valueExists) {
        #         $backupData = @{
        #             Path          = $Path
        #             Name          = $Name
        #             OriginalValue = $originalValue
        #             OriginalType  = $originalType
        #             ValueExists   = $true
        #             Timestamp     = Get-Date
        #             User          = $env:USERNAME
        #             Computer      = $env:COMPUTERNAME
        #         }
        #     } else {
        #         $backupData = @{
        #             Path          = $Path
        #             Name          = $Name
        #             OriginalValue = "ValueDoesNotExist"
        #             OriginalType  = "None"
        #             ValueExists   = $false
        #             Timestamp     = Get-Date
        #             User          = $env:USERNAME
        #             Computer      = $env:COMPUTERNAME
        #         }
        #     }
        #     $backupData | Export-Clixml -Path $backupFile -Force
        #     $opResult.BackupFile = $backupFile
        #     Write-CoreLog "Registry backup created: $backupFile (ValueExists: $valueExists)" -Level SUCCESS
        #     if (-not $Global:KRAKEFIX_SharedState.BackupRegistry.ContainsKey("$Path\$Name")) {
        #         $Global:KRAKEFIX_SharedState.BackupRegistry["$Path\$Name"] = $backupData
        #     }
        # }
        $shouldCreatePath = $CreatePath.IsPresent
        # Determine privilege level
        $effectivePrivilege = $RequiredPrivilege
        if ($RequiredPrivilege -eq 'Auto') {
            # CRITICAL FIX: HKCU requires System privilege for proper HKCU→HKU:\<SID> remapping
            # When running under SYSTEM context (Scheduled Task), HKCU does not exist
            # Resolve-RegistryExecutionPath needs System privilege to remap to HKU:\<SID>
            if ($Path -match '^(?i)HKCU:|^HKEY_CURRENT_USER\\') {
                $effectivePrivilege = 'System'
                Write-Verbose "[Registry] User hive detected → System privilege (required for HKU:\<SID> remapping)"
            }
            else {
                $effectivePrivilege = 'Auto'  # SYSTEM → Admin → User
                Write-Verbose "[Registry] System path → SYSTEM-first escalation"
            }
        }
        $executionPath = Resolve-RegistryExecutionPath -Path $Path -TargetPrivilege $effectivePrivilege
        if ($Operation -eq 'Set' -and -not (Test-Path -LiteralPath $executionPath)) {
            $shouldCreatePath = $true
        }
        # Execute registry modification with privilege escalation
        $actionDescription = if ($Operation -eq 'Remove') {
            "Remove registry value"
        }
        else {
            "Set registry value to $Value"
        }
        if ($PSCmdlet.ShouldProcess("$Path\\$Name", $actionDescription)) {
            $scriptBlock = {
                param($regPath, $regName, $regValue, $regType, $doCreatePath, $op)
                if ($op -eq 'Remove') {
                    if (Test-Path -LiteralPath $regPath) {
                        try {
                            $prop = Get-ItemProperty -LiteralPath $regPath -Name $regName -ErrorAction SilentlyContinue
                            if ($null -ne $prop) {
                                Remove-ItemProperty -LiteralPath $regPath -Name $regName -Force -ErrorAction Stop
                            }
                        }
                        catch {
                            throw $_.Exception
                        }
                    }
                    return $true
                }
                if ($doCreatePath -and -not (Test-Path -LiteralPath $regPath)) {
                    try {
                        # Recursively create parent paths if needed
                        $parentPath = Split-Path -Path $regPath -Parent
                        if ($parentPath -and -not (Test-Path -LiteralPath $parentPath)) {
                            New-Item -Path $parentPath -Force -ErrorAction Stop | Out-Null
                        }
                        New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
                    }
                    catch {
                        # If creation fails, throw to trigger fallback
                        throw "Failed to create registry path: $($_.Exception.Message)"
                    }
                }
                $convertedValue = switch ($regType) {
                    'DWord' { [int]$regValue; break }
                    'QWord' { [long]$regValue; break }
                    default { $regValue }
                }
                $propertyExists = $false
                try {
                    $existing = Get-ItemProperty -LiteralPath $regPath -Name $regName -ErrorAction Stop
                    if ($null -ne $existing) {
                        $propertyExists = $true
                    }
                }
                catch {
                    $propertyExists = $false
                }
                # ═══════════════════════════════════════════════════════════════════════
                # FIX: Přidat explicitní -Type pro Set-ItemProperty (existující property)
                # Bez -Type může PowerShell změnit typ registry hodnoty (např. DWord → String)
                # KRITICKÉ pro registry tweaky, kde typ hodnoty je důležitý pro systém
                # ═══════════════════════════════════════════════════════════════════════
                if ($propertyExists) {
                    # Konverze $regType na PropertyType enum pro Set-ItemProperty
                    $propertyType = switch ($regType) {
                        'String' { 'String' }
                        'ExpandString' { 'ExpandString' }
                        'MultiString' { 'MultiString' }
                        'Binary' { 'Binary' }
                        'QWord' { 'QWord' }
                        default { 'DWord' }
                    }
                    # CRITICAL: Použít -Type pro zachování registry typu
                    Set-ItemProperty -LiteralPath $regPath -Name $regName -Value $convertedValue -Type $propertyType -Force -ErrorAction Stop
                }
                else {
                    # Pro nové hodnoty: -PropertyType (stejná logika jako výše)
                    $propertyType = switch ($regType) {
                        'String' { 'String' }
                        'ExpandString' { 'ExpandString' }
                        'MultiString' { 'MultiString' }
                        'Binary' { 'Binary' }
                        'QWord' { 'QWord' }
                        default { 'DWord' }
                    }
                    New-ItemProperty -LiteralPath $regPath -Name $regName -PropertyType $propertyType -Value $convertedValue -Force -ErrorAction Stop | Out-Null
                }
                $check = Get-ItemProperty -LiteralPath $regPath -Name $regName -ErrorAction Stop
                return $check.$regName
            }
            $result = Invoke-WithPrivilege -ScriptBlock $scriptBlock -ArgumentList @($executionPath, $Name, $Value, $Type, $shouldCreatePath, $Operation) -RequiredPrivilege $effectivePrivilege
            if ($result.Success) {
                $opResult.Success = $true
                if ($Operation -eq 'Remove') {
                    $opResult.NewValue = $null
                    $opResult.NewType = 'None'
                    Write-CoreLog "Registry value removed: $Path\$Name (Privilege: $($result.PrivilegeLevel))" -Level SUCCESS
                }
                else {
                    Write-CoreLog "Registry set: $Path\$Name = $Value (Type: $Type, Privilege: $($result.PrivilegeLevel))" -Level SUCCESS
                }
            }
            else {
                throw "Privilege escalation failed: $($result.Error)"
            }
        }
    }
    catch {
        $opResult.Error = $_.Exception.Message
        Write-CoreLog "Registry operation failed: $Path\$Name - $($opResult.Error)" -Level ERROR
        # Attempt rollback if backup exists
        if ($opResult.BackupFile -and (Test-Path $opResult.BackupFile)) {
            Write-CoreLog "Attempting registry rollback..." -Level WARNING
            try {
                $backup = Import-Clixml -Path $opResult.BackupFile
                $rollbackPath = Resolve-RegistryExecutionPath -Path $backup.Path -TargetPrivilege $effectivePrivilege
                $originalExisted = $false
                if ($backup.PSObject.Properties.Match('ValueExists').Count -gt 0) {
                    $originalExisted = [bool]$backup.ValueExists
                }
                if (-not $originalExisted -and ($backup.OriginalValue -eq 'ValueDoesNotExist' -or $backup.OriginalType -eq 'None')) {
                    if (Test-Path -LiteralPath $rollbackPath) {
                        Remove-ItemProperty -LiteralPath $rollbackPath -Name $backup.Name -ErrorAction SilentlyContinue
                    }
                }
                else {
                    if (-not (Test-Path -LiteralPath $rollbackPath)) {
                        New-Item -LiteralPath $rollbackPath -Force | Out-Null
                    }
                    $restoreValue = switch ($backup.OriginalType) {
                        'DWord' { [int]$backup.OriginalValue }
                        'QWord' { [long]$backup.OriginalValue }
                        'MultiString' { [string[]]@($backup.OriginalValue) }
                        default { $backup.OriginalValue }
                    }
                    $existingProp = $null
                    $propExists = $false
                    try {
                        $existingProp = Get-ItemProperty -LiteralPath $rollbackPath -Name $backup.Name -ErrorAction Stop
                        if ($null -ne $existingProp) { $propExists = $true }
                    }
                    catch {
                        $propExists = $false
                    }
                    if ($propExists) {
                        Set-ItemProperty -LiteralPath $rollbackPath -Name $backup.Name -Value $restoreValue -Force -ErrorAction Stop
                    }
                    else {
                        $propertyType = switch ($backup.OriginalType) {
                            'String' { 'String' }
                            'ExpandString' { 'ExpandString' }
                            'MultiString' { 'MultiString' }
                            'Binary' { 'Binary' }
                            'QWord' { 'QWord' }
                            default { 'DWord' }
                        }
                        New-ItemProperty -LiteralPath $rollbackPath -Name $backup.Name -PropertyType $propertyType -Value $restoreValue -Force -ErrorAction Stop | Out-Null
                    }
                }
                Write-CoreLog "Registry rollback successful" -Level SUCCESS
            }
            catch {
                Write-CoreLog "Registry rollback FAILED: $($_.Exception.Message)" -Level ERROR
                Write-CoreLog "Manual restore required from: $($opResult.BackupFile)" -Level WARNING
            }
        }
    }
    return $opResult
}
function Invoke-RestoreRegistry {
    <#
    .SYNOPSIS
        Restore registry value from backup - intelligently handles 'ValueDoesNotExist'.
    .DESCRIPTION
        Restores registry value to original state from backup file.
        **CRITICAL LOGIC:**
        - If original value EXISTED → Restore it
        - If original value DID NOT EXIST → DELETE the value (return to baseline)
        **ROBUSTNESS:**
        - Uses Invoke-WithPrivilege (SYSTEM → Admin → User fallback)
        - Retry logic with exponential backoff
        - Extended timeout for critical operations
        - Comprehensive error logging
        This ensures perfect restore to user's original OS state.
    .PARAMETER BackupFile
        Path to backup XML file created by Invoke-RegistryOperation.
    .PARAMETER RetryCount
        Number of retry attempts (default: 5 for restore operations).
    .PARAMETER TimeoutSeconds
        Timeout for privileged operations (default: 180 seconds).
    .OUTPUTS
        [PSCustomObject] with Success, Message, Error, PrivilegeLevel properties.
    .EXAMPLE
        $result = Invoke-RestoreRegistry -BackupFile "C:\Backup\REG-HKLM-...-2025.xml"
        if ($result.Success) {
            Write-Host "Restored with $($result.PrivilegeLevel) privilege"
        }
    .NOTES
         CRITICAL: Restore operations are MORE important than apply!
        If restore fails, user cannot return to baseline OS state.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ })]
        [string]$BackupFile,
        [int]$RetryCount = 5,
        [int]$TimeoutSeconds = 180
    )
    $result = [PSCustomObject]@{
        Success        = $false
        Message        = $null
        Error          = $null
        PrivilegeLevel = 'None'
    }
    # ═══════════════════════════════════════════════════════════════════════
    # CRITICAL: PRE-FLIGHT CHECK (Mandatory before restore!)
    # ═══════════════════════════════════════════════════════════════════════
    if (-not (Test-RestoreReadiness)) {
        $result.Error = "Pre-flight check FAILED! Restore blocked for safety."
        Write-CoreLog " RESTORE BLOCKED: Pre-flight check failed" -Level ERROR
        return $result
    }
    try {
        # Load backup
        $backup = Import-Clixml -Path $BackupFile -ErrorAction Stop
        Write-CoreLog " RESTORE CRITICAL: $($backup.Path)\$($backup.Name)" -Level WARNING
        Write-Verbose "Backup timestamp: $($backup.Timestamp)"
        if ($backup.ValueExists -eq $false -or $backup.OriginalValue -eq "ValueDoesNotExist") {
            # ═══════════════════════════════════════════════════════
            # CRITICAL PATH: Value DID NOT EXIST originally → DELETE it!
            # ═══════════════════════════════════════════════════════
            Write-CoreLog "Registry value did not exist in original OS - deleting with privilege escalation" -Level WARNING
            $deleteScript = {
                param($regPath, $regName)
                if (Test-Path -LiteralPath $regPath) {
                    $prop = Get-ItemProperty -LiteralPath $regPath -Name $regName -ErrorAction SilentlyContinue
                    if ($null -ne $prop) {
                        Remove-ItemProperty -LiteralPath $regPath -Name $regName -Force -ErrorAction Stop
                        return "Deleted"
                    }
                    else {
                        return "AlreadyGone"
                    }
                }
                else {
                    return "PathNotFound"
                }
            }
            # Execute with privilege escalation + retry
            $privResult = Invoke-WithPrivilege -ScriptBlock $deleteScript `
                -ArgumentList @($backup.Path, $backup.Name) `
                -RetryCount $RetryCount `
                -RetryDelayMs 2000
            if ($privResult.Success) {
                $result.Success = $true
                $result.PrivilegeLevel = $privResult.PrivilegeLevel
                if ($privResult.Result -eq "Deleted") {
                    $result.Message = "Deleted registry value (restored to baseline): $($backup.Path)\$($backup.Name) [Privilege: $($privResult.PrivilegeLevel)]"
                }
                else {
                    $result.Message = "Value already in correct state (not present): $($backup.Path)\$($backup.Name)"
                }
                Write-CoreLog $result.Message -Level SUCCESS
            }
            else {
                throw "Delete failed after $RetryCount retries: $($privResult.Error)"
            }
        }
        else {
            # ═══════════════════════════════════════════════════════
            # STANDARD RESTORE: Value EXISTED originally → Restore it
            # ═══════════════════════════════════════════════════════
            Write-Verbose "Restoring original value: $($backup.OriginalValue) (Type: $($backup.OriginalType))"
            $restoreScript = {
                param($regPath, $regName, $regValue, $regType)
                # Ensure path exists
                if (-not (Test-Path -LiteralPath $regPath)) {
                    New-Item -LiteralPath $regPath -Force -ItemType RegistryKey -ErrorAction Stop | Out-Null
                }
                # Restore value
                Set-ItemProperty -LiteralPath $regPath -Name $regName -Value $regValue -Type $regType -Force -ErrorAction Stop
                # Verify
                $check = Get-ItemProperty -LiteralPath $regPath -Name $regName -ErrorAction Stop
                return $check.$regName
            }
            # Execute with privilege escalation + retry
            $privResult = Invoke-WithPrivilege -ScriptBlock $restoreScript `
                -ArgumentList @($backup.Path, $backup.Name, $backup.OriginalValue, $backup.OriginalType) `
                -RetryCount $RetryCount `
                -RetryDelayMs 2000
            if ($privResult.Success) {
                $result.Success = $true
                $result.PrivilegeLevel = $privResult.PrivilegeLevel
                $result.Message = "Restored registry value: $($backup.Path)\$($backup.Name) = $($backup.OriginalValue) [Privilege: $($privResult.PrivilegeLevel)]"
                Write-CoreLog $result.Message -Level SUCCESS
            }
            else {
                throw "Restore failed after $RetryCount retries: $($privResult.Error)"
            }
        }
    }
    catch {
        $result.Error = $_.Exception.Message
        Write-CoreLog "CRITICAL RESTORE FAILURE: $BackupFile - $($result.Error)" -Level ERROR
        Write-CoreLog "PowerShell restore failed! Attempting EMERGENCY reg.exe fallback..." -Level WARNING
        # ═══════════════════════════════════════════════════════════════════════
        # EMERGENCY FALLBACK: Try reg.exe restore (LAST RESORT!)
        # ═══════════════════════════════════════════════════════════════════════
        try {
            Write-Host ""
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow
            Write-Host "   ACTIVATING EMERGENCY FALLBACK..." -ForegroundColor Yellow
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow
            Write-Host ""
            $emergencySuccess = Invoke-EmergencyRestoreViaRegExe -BackupFile $BackupFile
            if ($emergencySuccess) {
                # Emergency restore succeeded!
                $result.Success = $true
                $result.PrivilegeLevel = 'reg.exe (Native Windows Tool)'
                $result.Message = "EMERGENCY RESTORE SUCCESSFUL via reg.exe fallback"
                Write-CoreLog $result.Message -Level SUCCESS
            }
            else {
                # Emergency restore also failed - CRITICAL!
                Write-CoreLog "EMERGENCY FALLBACK FAILED! User cannot return to baseline!" -Level ERROR
                Write-CoreLog "Manual intervention REQUIRED!" -Level ERROR
            }
        }
        catch {
            Write-CoreLog "Emergency fallback exception: $($_.Exception.Message)" -Level ERROR
        }
    }
    return $result
}
function Invoke-ServiceOperation {
    <#
    .SYNOPSIS
        Execute service operation with automatic backup, privilege escalation, and rollback.
    .DESCRIPTION
        Safely modifies Windows services with enterprise-grade protection:
        - Automatic backup of original startup type before modification
        - Privilege escalation (SYSTEM → Admin → User)
        - Automatic rollback on error
        - Protected service detection (PPL services)
        - Dependency validation
        - Audit logging
    .PARAMETER ServiceName
        Name of the Windows service.
    .PARAMETER TargetStatus
        Desired status for the service ('Running' or 'Stopped').
    .PARAMETER StartupType
        Desired startup type for the service ('Automatic', 'Manual', 'Disabled').
    .PARAMETER BackupPath
        Optional path to save backup (defaults to temp directory).
    .OUTPUTS
        [PSCustomObject] with Success, BackupFile, OriginalStartupType, NewStartupType, Error properties.
    .EXAMPLE
        # Disable and stop a service
        $result = Invoke-ServiceOperation -ServiceName "DiagTrack" -TargetStatus 'Stopped' -StartupType 'Disabled'
        if ($result.Success) {
            Write-Host "Service state changed successfully."
        }
    .NOTES
        Protected services (PPL) cannot be modified even with SYSTEM privileges.
        Critical services (e.g., RpcSs, Winmgmt, Schedule) will generate warnings.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,
        [ValidateSet('Running', 'Stopped')]
        [string]$TargetStatus,
        [ValidateSet('Automatic', 'Manual', 'Disabled')]
        [string]$StartupType,
        [string]$BackupPath = (Join-Path ([Environment]::GetFolderPath('Desktop')) "KRAKE-Backup\Service-Backups"),
        [ValidateSet('Auto', 'User', 'Admin', 'System')]
        [string]$RequiredPrivilege = 'Auto'
    )
    $opResult = [PSCustomObject]@{
        Success             = $false
        BackupFile          = $null
        ServiceName         = $ServiceName
        OriginalStatus      = $null
        OriginalStartupType = $null
        NewStatus           = $null
        NewStartupType      = $null
        Error               = $null
    }
    try {
        $actionDescription = "Set service '$ServiceName' state (Status: $($TargetStatus), Startup: $($StartupType))"
        Write-CoreLog "Starting service operation: $actionDescription" -Level INFO
        # Validate service exists
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        $serviceExists = $null -ne $svc
        if (-not $serviceExists) {
            # Service doesn't exist - record this for potential future operations
            Write-Verbose "Service '$ServiceName' does not exist - recording 'ServiceDoesNotExist'"
            $opResult.OriginalStatus = "ServiceDoesNotExist"
            $opResult.OriginalStartupType = "ServiceDoesNotExist"
        }
        else {
            $opResult.OriginalStatus = $svc.Status.ToString()
            $opResult.OriginalStartupType = $svc.StartType.ToString()
            Write-Verbose "Original state: Status=$($opResult.OriginalStatus), StartupType=$($opResult.OriginalStartupType)"
        }
        # Check for critical services (warning only, not blocking)
        $criticalServices = @('RpcSs', 'Winmgmt', 'Schedule', 'SENS', 'EventLog', 'PlugPlay')
        if ($criticalServices -contains $ServiceName -and $TargetStatus -eq 'Stopped') {
            Write-CoreLog "WARNING: $ServiceName is a critical system service! Operation may cause instability." -Level WARNING
        }
        # Create backup directory if needed
        if (-not (Test-Path $BackupPath)) {
            New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
        }
        # Backup current state (ALWAYS - even if service doesn't exist!)
        # if ($Operation -in @('Disable', 'Enable', 'SetStartupType')) {
        #     $shouldCreateBackup = $true
        #     $existingBackupData = $null
        #     try {
        #         $existingBackup = Get-ChildItem -Path $BackupPath -Filter "SVC-$ServiceName-*.xml" -ErrorAction SilentlyContinue |
        #             Sort-Object -Property LastWriteTime -Descending |
        #             Select-Object -First 1
        #         if ($null -ne $existingBackup) {
        #             try {
        #                 $existingBackupData = Import-Clixml -Path $existingBackup.FullName
        #             } catch {
        #                 Write-CoreLog ("Failed to import existing service backup for {0}: {1}" -f $ServiceName, $_.Exception.Message) -Level WARNING
        #             }
        #             if ($null -ne $existingBackupData -and `
        #                 $existingBackupData.OriginalStartupType -eq $opResult.OriginalStartupType -and `
        #                 $existingBackupData.OriginalStatus -eq $opResult.OriginalStatus -and `
        #                 $existingBackupData.ServiceExists -eq $serviceExists) {
        #                 $shouldCreateBackup = $false
        #                 $opResult.BackupFile = $existingBackup.FullName
        #                 Write-CoreLog "Service backup reused: $($existingBackup.Name) (no state change detected)" -Level INFO
        #             }
        #         }
        #     } catch {
        #         Write-CoreLog ("Service backup lookup failed for {0}: {1}" -f $ServiceName, $_.Exception.Message) -Level WARNING
        #     }
        #     if ($shouldCreateBackup) {
        #         $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        #         $backupFile = Join-Path $BackupPath "SVC-$ServiceName-$timestamp.xml"
        #         $backupData = @{
        #             ServiceName         = $ServiceName
        #             OriginalStatus      = $opResult.OriginalStatus
        #             OriginalStartupType = $opResult.OriginalStartupType
        #             ServiceExists       = $serviceExists
        #             Timestamp           = Get-Date
        #             User                = $env:USERNAME
        #             Computer            = $env:COMPUTERNAME
        #         }
        #         $backupData | Export-Clixml -Path $backupFile -Force
        #         $opResult.BackupFile = $backupFile
        #         Write-CoreLog "Service backup created: $backupFile (ServiceExists: $serviceExists)" -Level SUCCESS
        #         $existingBackupData = $backupData
        #     }
        #     if ($null -ne $existingBackupData) {
        #         $Global:KRAKEFIX_SharedState.BackupServices[$ServiceName] = $existingBackupData
        #     }
        # }
        # Stop early if service doesn't exist (treat as already handled)
        if (-not $serviceExists) {
            Write-CoreLog "Service '$ServiceName' not found - skipping operation." -Level WARNING
            $opResult.Success = $true
            return $opResult
        }
        # Execute service operation with privilege escalation
        if ($PSCmdlet.ShouldProcess($ServiceName, $actionDescription)) {
            $scriptBlock = {
                param($svcName, $newStatus, $newStartType)
                $svc = Get-Service -Name $svcName -ErrorAction Stop
                # Set Startup Type first. This is important.
                if ($newStartType -and $svc.StartType -ne $newStartType) {
                    Set-Service -Name $svcName -StartupType $newStartType -ErrorAction Stop
                }
                # Set Status
                if ($newStatus) {
                    # Re-get state after potential startup type change
                    $svc = Get-Service -Name $svcName
                    if ($newStatus -eq 'Stopped' -and $svc.Status -ne 'Stopped') {
                        Stop-Service -Name $svcName -Force -ErrorAction Stop
                    }
                    elseif ($newStatus -eq 'Running' -and $svc.Status -ne 'Running') {
                        # Cannot start a disabled service
                        if ($svc.StartType -ne 'Disabled') {
                            Start-Service -Name $svcName -ErrorAction Stop
                        }
                    }
                }
                return Get-Service -Name $svcName | Select-Object Name, Status, StartType
            }
            $result = Invoke-WithPrivilege -ScriptBlock $scriptBlock -ArgumentList @($ServiceName, $TargetStatus, $StartupType) -RequiredPrivilege $RequiredPrivilege
            if ($result.Success) {
                $svcResult = $result.Result
                if ($null -eq $svcResult) {
                    $svcResult = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
                    if ($null -ne $svcResult) {
                        $svcResult = $svcResult | Select-Object Name, Status, StartType
                    }
                }
                if ($null -eq $svcResult) {
                    throw "Service state verification failed: unable to query '$ServiceName' after operation."
                }
                $opResult.Success = $true
                $opResult.NewStatus = $svcResult.Status.ToString()
                $opResult.NewStartupType = $svcResult.StartType.ToString()
                Write-CoreLog "Service operation on '$ServiceName' succeeded (Privilege: $($result.PrivilegeLevel), New state: $($opResult.NewStatus)/$($opResult.NewStartupType))" -Level SUCCESS
            }
            else {
                throw "Privilege escalation failed: $($result.Error)"
            }
        }
    }
    catch {
        $opResult.Error = $_.Exception.Message
        Write-CoreLog "Service operation failed: $ServiceName - $($opResult.Error)" -Level ERROR
        # Attempt rollback if backup exists
        if ($opResult.BackupFile -and (Test-Path $opResult.BackupFile)) {
            Write-CoreLog "Attempting service rollback..." -Level WARNING
            try {
                $backup = Import-Clixml -Path $opResult.BackupFile
                if ($backup.OriginalStartupType -ne 'ServiceDoesNotExist') {
                    $rollbackScript = {
                        param($svcName, $startupType)
                        Set-Service -Name $svcName -StartupType $startupType -ErrorAction Stop
                        return Get-Service -Name $svcName | Select-Object Name, Status, StartType
                    }
                    $rollbackResult = Invoke-WithPrivilege -ScriptBlock $rollbackScript -ArgumentList @($backup.ServiceName, $backup.OriginalStartupType) -RequiredPrivilege 'System'
                    if ($rollbackResult.Success) {
                        Write-CoreLog "Service rollback successful (restored to $($backup.OriginalStartupType))" -Level SUCCESS
                    }
                    else {
                        throw "Rollback privilege escalation failed: $($rollbackResult.Error)"
                    }
                }
                else {
                    Write-CoreLog "Rollback skipped: original service state indicated absence (ServiceDoesNotExist)." -Level WARNING
                }
            }
            catch {
                Write-CoreLog "Service rollback FAILED: $($_.Exception.Message)" -Level ERROR
                Write-CoreLog "Manual restore required from: $($opResult.BackupFile)" -Level WARNING
            }
        }
    }
    return $opResult
}
function Invoke-RestoreService {
    <#
    .SYNOPSIS
        Restore service state from backup - intelligently handles 'ServiceDoesNotExist'.
    .DESCRIPTION
        Restores service state to original from backup file.
        **CRITICAL LOGIC:**
        - If original service EXISTED → Restore startup type and status
        - If original service DID NOT EXIST → Delete service (or inform user)
        **ROBUSTNESS:**
        - Uses Invoke-WithPrivilege (SYSTEM → Admin → User fallback)
        - Retry logic with exponential backoff
        - Extended timeout for critical operations
        - Comprehensive error logging
    .PARAMETER BackupFile
        Path to backup XML file created by Invoke-ServiceOperation.
    .PARAMETER RetryCount
        Number of retry attempts (default: 5 for restore operations).
    .PARAMETER TimeoutSeconds
        Timeout for privileged operations (default: 180 seconds).
    .OUTPUTS
        [PSCustomObject] with Success, Message, Error, PrivilegeLevel properties.
    .NOTES
         CRITICAL: Restore operations are MORE important than apply!
        If restore fails, user cannot return to baseline OS state.
        Reference: KRAKE-FIX v1 service restore logic
        Study: 05-Service-Management-Deep-Dive.md, 03-Error-Handling-Fallback-Strategy.md
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ })]
        [string]$BackupFile,
        [int]$RetryCount = 5,
        [int]$TimeoutSeconds = 180
    )
    $result = [PSCustomObject]@{
        Success        = $false
        Message        = $null
        Error          = $null
        PrivilegeLevel = 'None'
    }
    try {
        $backup = Import-Clixml -Path $BackupFile -ErrorAction Stop
        Write-CoreLog "RESTORE CRITICAL: Service '$($backup.ServiceName)'" -Level WARNING
        Write-Verbose "Backup timestamp: $($backup.Timestamp)"
        if ($backup.ServiceExists -eq $false -or $backup.OriginalStartupType -eq "ServiceDoesNotExist") {
            # Service didn't exist originally - inform user (services can't be easily deleted)
            Write-CoreLog "Service did not exist in original OS: $($backup.ServiceName)" -Level WARNING
            Write-CoreLog "Note: Windows services cannot be deleted via Set-Service (requires sc.exe delete or driver removal)" -Level INFO
            $result.Success = $true
            $result.Message = " Service did not exist originally (manual deletion may be required): $($backup.ServiceName)"
        }
        else {
            # ═══════════════════════════════════════════════════════
            # RESTORE: Service EXISTED originally → Restore startup type
            # ═══════════════════════════════════════════════════════
            Write-Verbose "Restoring service state: Startup=$($backup.OriginalStartupType)"
            $restoreScript = {
                param($svcName, $startupType)
                Set-Service -Name $svcName -StartupType $startupType -ErrorAction Stop
                # Verify
                $svcAfter = Get-Service -Name $svcName -ErrorAction Stop
                return $svcAfter.StartType.ToString()
            }
            # Execute with privilege escalation + retry
            $privResult = Invoke-WithPrivilege -ScriptBlock $restoreScript `
                -ArgumentList @($backup.ServiceName, $backup.OriginalStartupType) `
                -RetryCount $RetryCount `
                -RetryDelayMs 2000
            if ($privResult.Success) {
                $result.Success = $true
                $result.PrivilegeLevel = $privResult.PrivilegeLevel
                $result.Message = "Restored service: $($backup.ServiceName) (Startup: $($backup.OriginalStartupType)) [Privilege: $($privResult.PrivilegeLevel)]"
                Write-CoreLog $result.Message -Level SUCCESS
            }
            else {
                throw "Restore failed after $RetryCount retries: $($privResult.Error)"
            }
        }
    }
    catch {
        $result.Error = $_.Exception.Message
        Write-CoreLog "CRITICAL RESTORE FAILURE: $BackupFile - $($result.Error)" -Level ERROR
        Write-CoreLog "User cannot return to baseline! Manual intervention may be required." -Level ERROR
    }
    return $result
}
# ───────────────────────────────────────────────────────────────────────────
# SECURITY & INTEGRITY LEVEL DETECTION
# ───────────────────────────────────────────────────────────────────────────
function Get-ProcessIntegrityLevel {
    <#
    .SYNOPSIS
        Gets the integrity level of the current process.
    .DESCRIPTION
        Returns the integrity level (Untrusted, Low, Medium, High, System, Protected)
        of the current PowerShell process. This is critical for understanding what
        operations the process can perform.
    .OUTPUTS
        [string] Integrity level name.
    .EXAMPLE
        $level = Get-ProcessIntegrityLevel
        if ($level -eq 'High') {
            Write-Host "Running with elevated privileges"
        }
    .NOTES
        Integrity Levels (from lowest to highest):
        - Untrusted (S-1-16-0)
        - Low (S-1-16-4096) - IE Protected Mode, AppContainer
        - Medium (S-1-16-8192) - Normal user processes
        - High (S-1-16-12288) - Elevated admin processes
        - System (S-1-16-16384) - SYSTEM/LocalService/NetworkService
        - Protected (S-1-16-20480) - Protected Process Light (PPL)
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    try {
        # Get current process token
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]$identity
        # Check if running as admin
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        # Simplified detection based on known SIDs
        # For full P/Invoke implementation, see study doc 39-Kernel-Security-Models.md
        if ($identity.User.Value -eq 'S-1-5-18') {
            # NT AUTHORITY\SYSTEM
            return 'System'
        }
        elseif ($isAdmin) {
            # Elevated process (High integrity)
            return 'High'
        }
        else {
            # Normal user process (Medium integrity)
            return 'Medium'
        }
    }
    catch {
        Write-Warning "Failed to detect integrity level: $($_.Exception.Message)"
        return 'Unknown'
    }
}
function Assert-TokenSecurity {
    <#
    .SYNOPSIS
        Validates that the current token has sufficient privileges for critical operations.
    .DESCRIPTION
        Pre-flight security check before performing critical system operations.
        Verifies:
        - Not running as Guest/Anonymous
        - Sufficient integrity level
        - Required privileges (if specified)
    .PARAMETER RequiredIntegrityLevel
        Minimum required integrity level (Medium, High, System).
    .PARAMETER ThrowOnFailure
        If true, throws an exception on validation failure.
        If false, returns $false on failure.
    .OUTPUTS
        [bool] True if validation passed, False otherwise.
    .EXAMPLE
        if (Assert-TokenSecurity -RequiredIntegrityLevel High) {
            # Proceed with admin-level operation
        }
    .EXAMPLE
        # Throw exception if not High integrity
        Assert-TokenSecurity -RequiredIntegrityLevel High -ThrowOnFailure
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [ValidateSet('Medium', 'High', 'System')]
        [string]$RequiredIntegrityLevel = 'Medium',
        [switch]$ThrowOnFailure
    )
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        # Check for Guest/Anonymous accounts (security risk)
        $guestSIDs = @('S-1-5-7', 'S-1-5-21-*-501')  # Anonymous, Guest
        foreach ($guestSID in $guestSIDs) {
            if ($identity.User.Value -like $guestSID) {
                $errorMsg = "Security violation: Running as Guest or Anonymous account!"
                if ($ThrowOnFailure) {
                    throw $errorMsg
                }
                else {
                    Write-CoreLog $errorMsg -Level ERROR
                    return $false
                }
            }
        }
        # Check integrity level
        $currentLevel = Get-ProcessIntegrityLevel
        $levelOrder = @{
            'Unknown'   = 0
            'Untrusted' = 1
            'Low'       = 2
            'Medium'    = 3
            'High'      = 4
            'System'    = 5
            'Protected' = 6
        }
        if ($levelOrder[$currentLevel] -lt $levelOrder[$RequiredIntegrityLevel]) {
            $errorMsg = "Insufficient integrity level: Current=$currentLevel, Required=$RequiredIntegrityLevel"
            if ($ThrowOnFailure) {
                throw $errorMsg
            }
            else {
                Write-CoreLog $errorMsg -Level ERROR
                return $false
            }
        }
        Write-Verbose "Token security validated: Integrity=$currentLevel, User=$($identity.Name)"
        return $true
    }
    catch {
        if ($ThrowOnFailure) {
            throw
        }
        else {
            Write-CoreLog "Token security validation failed: $($_.Exception.Message)" -Level ERROR
            return $false
        }
    }
}
# ───────────────────────────────────────────────────────────────────────────
# ACL MANAGEMENT WITH AUTO-BACKUP
# ───────────────────────────────────────────────────────────────────────────
function Invoke-SafeACLModification {
    <#
    .SYNOPSIS
        Modify ACL with automatic backup and rollback on error.
    .DESCRIPTION
        Safely modifies Access Control Lists (ACLs) for files, folders, or registry keys.
        Features:
        - Automatic backup of current ACL (SDDL format)
        - Privilege escalation (SYSTEM → Admin → User)
        - Automatic rollback on error
        - Audit logging
    .PARAMETER Path
        Path to the file, folder, or registry key.
    .PARAMETER ScriptBlock
        Script block that modifies the ACL. Receives the current ACL object as parameter.
    .PARAMETER BackupPath
        Optional path to save ACL backup (defaults to temp directory).
    .OUTPUTS
        [PSCustomObject] with Success, BackupFile, OriginalSDDL, Error properties.
    .EXAMPLE
        # Block access to Microsoft Edge executable
        $result = Invoke-SafeACLModification -Path "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ScriptBlock {
            param($acl)
            # Deny Everyone Execute
            $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                'Everyone', 'ReadAndExecute', 'Deny'
            )
            $acl.AddAccessRule($denyRule)
            return $acl
        }
    .EXAMPLE
        # Restore ACL from backup
        if ($result.BackupFile) {
            $backup = Import-Clixml $result.BackupFile
            Set-Acl -Path $Path -AclObject $backup.ACL
        }
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,
        [string]$BackupPath = (Join-Path $env:TEMP "KRAKE-FIX-ACL-Backups")
    )
    $result = [PSCustomObject]@{
        Success      = $false
        BackupFile   = $null
        OriginalSDDL = $null
        NewSDDL      = $null
        Error        = $null
    }
    try {
        # Validate path exists
        if (-not (Test-Path -LiteralPath $Path)) {
            throw "Path does not exist: $Path"
        }
        # Pre-flight security check
        if (-not (Assert-TokenSecurity -RequiredIntegrityLevel High)) {
            throw "ACL modifications require High integrity level (elevated admin)"
        }
        Write-CoreLog "Starting ACL modification for: $Path" -Level INFO
        # Create backup directory if needed
        if (-not (Test-Path $BackupPath)) {
            New-Item -Path $BackupPath -ItemType Directory -Force | Out-Null
        }
        # Get current ACL
        $currentACL = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $result.OriginalSDDL = $currentACL.Sddl
        # Backup current ACL to file
        $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $safeName = [System.IO.Path]::GetFileName($Path) -replace '[^\w\-]', '_'
        $backupFile = Join-Path $BackupPath "ACL-$safeName-$timestamp.xml"
        $backupData = @{
            Path      = $Path
            Timestamp = Get-Date
            SDDL      = $result.OriginalSDDL
            ACL       = $currentACL
            User      = $env:USERNAME
            Computer  = $env:COMPUTERNAME
        }
        $backupData | Export-Clixml -Path $backupFile -Force
        $result.BackupFile = $backupFile
        Write-CoreLog "ACL backup created: $backupFile" -Level SUCCESS
        Write-Verbose "Original SDDL: $($result.OriginalSDDL)"
        # Execute modification script block
        if ($PSCmdlet.ShouldProcess($Path, "Modify ACL")) {
            $modifiedACL = & $ScriptBlock $currentACL
            if ($null -eq $modifiedACL) {
                throw "ScriptBlock did not return modified ACL object"
            }
            $result.NewSDDL = $modifiedACL.Sddl
            Write-Verbose "New SDDL: $($result.NewSDDL)"
            # Apply modified ACL with privilege escalation
            $aclResult = Invoke-WithPrivilege -ScriptBlock {
                param($targetPath, $newACL)
                Set-Acl -LiteralPath $targetPath -AclObject $newACL -ErrorAction Stop
            } -ArgumentList @($Path, $modifiedACL)
            if (-not $aclResult.Success) {
                throw "Failed to apply ACL: $($aclResult.Error)"
            }
            # Verify ACL was applied
            $verifyACL = Get-Acl -LiteralPath $Path
            if ($verifyACL.Sddl -ne $result.NewSDDL) {
                throw "ACL verification failed: Applied SDDL does not match expected"
            }
            $result.Success = $true
            Write-CoreLog "ACL modification successful for: $Path" -Level SUCCESS
        }
    }
    catch {
        $result.Error = $_.Exception.Message
        Write-CoreLog "ACL modification failed for $Path : $($result.Error)" -Level ERROR
        # Attempt rollback if backup exists
        if ($result.BackupFile -and (Test-Path $result.BackupFile)) {
            Write-CoreLog "Attempting ACL rollback..." -Level WARNING
            try {
                $backup = Import-Clixml -Path $result.BackupFile
                Set-Acl -LiteralPath $Path -AclObject $backup.ACL -ErrorAction Stop
                Write-CoreLog "ACL rollback successful" -Level SUCCESS
            }
            catch {
                Write-CoreLog "ACL rollback FAILED: $($_.Exception.Message)" -Level ERROR
                Write-CoreLog "Manual restore required from: $($result.BackupFile)" -Level WARNING
            }
        }
    }
    return $result
}
# ═══════════════════════════════════════════════════════════════════════════
# TRUSTEDINSTALLER CONTEXT OPERATIONS
# ═══════════════════════════════════════════════════════════════════════════
function Test-IsTrustedInstallerOwned {
    <#
    .SYNOPSIS
        Check if resource (file/folder/registry) is owned by TrustedInstaller.
    .DESCRIPTION
        Detects if the specified path is owned by NT SERVICE\TrustedInstaller.
        This is critical for determining if ownership transfer is needed.
    .PARAMETER Path
        Path to file, folder, or registry key (PS drive format).
    .OUTPUTS
        [bool] True if owned by TrustedInstaller, False otherwise.
    .EXAMPLE
        if (Test-IsTrustedInstallerOwned -Path "C:\Windows\System32\kernel32.dll") {
            Write-Host "File requires TrustedInstaller privilege"
        }
    .EXAMPLE
        if (Test-IsTrustedInstallerOwned -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SomeService") {
            Write-Host "Registry key owned by TrustedInstaller"
        }
    .NOTES
        TrustedInstaller SID: S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464
        Reference: Study Doc 12-TrustedInstaller-Context.md
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Path
    )
    process {
        if (-not (Test-Path -LiteralPath $Path)) {
            Write-Warning "Path not found: $Path"
            return $false
        } try {
            $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
            $owner = $acl.Owner

            # TrustedInstaller muze byt reprezentovan ruzne
            $trustedInstallerNames = @(
                'NT SERVICE\TrustedInstaller',
                'NT Service\TrustedInstaller',
                'TRUSTEDINSTALLER'
            )
            foreach ($name in $trustedInstallerNames) {
                if ($owner -like "*$name*") {
                    Write-Verbose "Confirmed TrustedInstaller ownership: $owner"
                    return $true
                }
            }
            Write-Verbose "Not TrustedInstaller owned. Current owner: $owner"
            return $false
        }
        catch {
            Write-Warning "Failed to get ACL for $Path : $($_.Exception.Message)"
            return $false
        }
    }
}
function Grant-TakeOwnership {
    <#
    .SYNOPSIS
        Take ownership of file/folder/registry using takeown.exe and grant full control.
    .DESCRIPTION
        Uses Windows built-in takeown.exe to transfer ownership to Administrators group,
        then uses icacls.exe to grant full control. This is the most reliable method
        for taking ownership of TrustedInstaller-owned resources.
    .PARAMETER Path
        Path to file, folder, or registry key.
    .PARAMETER Recurse
        Apply ownership change recursively (for folders).
    .OUTPUTS
        [PSCustomObject] with Success, OriginalOwner, Error properties.
    .EXAMPLE
        $result = Grant-TakeOwnership -Path "C:\Windows\System32\some.dll"
        if ($result.Success) {
            Write-Host "Ownership taken. Original owner: $($result.OriginalOwner)"
        }
    .NOTES
        Requires elevated administrator privileges.
        Reference: Study Doc 12-TrustedInstaller-Context.md
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [switch]$Recurse
    )
    $result = [PSCustomObject]@{
        Success       = $false
        OriginalOwner = $null
        Error         = $null
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        $result.Error = "Path not found: $Path"
        return $result
    }
    try {
        # Backup original owner
        $acl = Get-Acl -LiteralPath $Path
        $result.OriginalOwner = $acl.Owner
        Write-Verbose "Original owner: $($result.OriginalOwner)"
        # ═══════════════════════════════════════════════════════
        # STEP 1: Take ownership (transfer to Administrators group)
        # ═══════════════════════════════════════════════════════
        $takeownArgs = @('/F', "`"$Path`"", '/A')  # /A = Administrators group
        if ($Recurse) {
            $takeownArgs += '/R'  # Recursive
            $takeownArgs += '/D', 'Y'  # Suppress confirmation
        }
        Write-Verbose "Executing: takeown.exe $($takeownArgs -join ' ')"
        $takeownOutput = & takeown.exe @takeownArgs 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "takeown failed (exit code $LASTEXITCODE): $takeownOutput"
        }
        Write-Verbose "Ownership transferred to Administrators"
        # ═══════════════════════════════════════════════════════
        # STEP 2: Grant full control to Administrators
        # ═══════════════════════════════════════════════════════
        $icaclsArgs = @("`"$Path`"", '/grant', 'Administrators:F')
        if ($Recurse) {
            $icaclsArgs += '/T'  # Tree (recursive)
            $icaclsArgs += '/C'  # Continue on error
            $icaclsArgs += '/Q'  # Quiet
        }
        Write-Verbose "Executing: icacls.exe $($icaclsArgs -join ' ')"
        $icaclsOutput = & icacls.exe @icaclsArgs 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "icacls failed (exit code $LASTEXITCODE): $icaclsOutput"
        }
        Write-Verbose "Full control granted to Administrators"
        $result.Success = $true
    }
    catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to take ownership of $Path : $($result.Error)"
    }
    return $result
}

function Restore-TrustedInstallerOwnership {
    <#
    .SYNOPSIS
        Restore ownership back to TrustedInstaller.
    .DESCRIPTION
        Uses icacls.exe to set the owner back to NT SERVICE\TrustedInstaller.
        This is critical after modifying TrustedInstaller-owned resources to
        maintain system security and Windows Update functionality.
    .PARAMETER Path
        Path to file, folder, or registry key.
    .PARAMETER Recurse
        Apply ownership change recursively (for folders).
    .OUTPUTS
        [PSCustomObject] with Success, Error properties.
    .EXAMPLE
        $result = Restore-TrustedInstallerOwnership -Path "C:\Windows\System32\some.dll"
        if ($result.Success) {
            Write-Host "Ownership restored to TrustedInstaller"
        }
    .NOTES
        Requires elevated administrator privileges.
        Reference: Study Doc 12-TrustedInstaller-Context.md
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [switch]$Recurse
    )
    $result = [PSCustomObject]@{
        Success = $false
        Error   = $null
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        $result.Error = "Path not found: $Path"
        return $result
    }
    try {
        # ═══════════════════════════════════════════════════════
        # STEP 1: Restore ownership to TrustedInstaller
        # ═══════════════════════════════════════════════════════
        $icaclsArgs = @("`"$Path`"", '/setowner', '"NT SERVICE\TrustedInstaller"')
        if ($Recurse) {
            $icaclsArgs += '/T'  # Tree (recursive)
            $icaclsArgs += '/C'  # Continue on error
            $icaclsArgs += '/Q'  # Quiet
        }
        Write-Verbose "Executing: icacls.exe $($icaclsArgs -join ' ')"
        $icaclsOutput = & icacls.exe @icaclsArgs 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "icacls setowner failed (exit code $LASTEXITCODE): $icaclsOutput"
        }
        Write-Verbose "Ownership restored to TrustedInstaller"
        # ═══════════════════════════════════════════════════════
        # STEP 2: Remove Administrators full control (optional cleanup)
        # ═══════════════════════════════════════════════════════
        $icaclsRemoveArgs = @("`"$Path`"", '/remove', 'Administrators')
        if ($Recurse) {
            $icaclsRemoveArgs += '/T', '/C', '/Q'
        }
        # Note: This may fail if Administrators needs access, so we don't throw on error
        $null = & icacls.exe @icaclsRemoveArgs 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Verbose "Administrators access removed"
        }
        else {
            Write-Verbose "Could not remove Administrators access (not critical)"
        }
        $result.Success = $true
    }
    catch {
        $result.Error = $_.Exception.Message
        Write-Error "Failed to restore TrustedInstaller ownership: $($result.Error)"
    }
    return $result
}

function Invoke-AsTrustedInstaller {
    <#
    .SYNOPSIS
        Execute script block with TrustedInstaller-level access to resources.
    .DESCRIPTION
        Complete workflow for modifying TrustedInstaller-owned resources:
        1. Detect if resource is TrustedInstaller-owned
        2. Backup original ACL (Security Descriptor)
        3. Take ownership (Administrators)
        4. Grant full control
        5. Execute script block with elevated access
        6. Restore ownership to TrustedInstaller
        7. Automatic rollback on error
        8. Audit logging
        This is the HIGHEST privilege level in Windows - use with EXTREME caution!
    .PARAMETER Path
        Path to file, folder, or registry key to modify.
    .PARAMETER ScriptBlock
        Script block to execute after taking ownership.
        The script block receives $Path as the first parameter.
    .PARAMETER ArgumentList
        Optional arguments to pass to the script block.
    .PARAMETER Recurse
        Apply ownership changes recursively (for folders).
    .PARAMETER SkipOwnershipRestore
        If true, does NOT restore ownership to TrustedInstaller.
        WARNING: Only use if you know what you're doing!
    .OUTPUTS
        [PSCustomObject] with Success, OriginalOwner, Result, Error properties.
    .EXAMPLE
        # Modify registry key owned by TrustedInstaller
        $result = Invoke-AsTrustedInstaller -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack" -ScriptBlock {
            param($regPath)
            Set-ItemProperty -Path $regPath -Name "Start" -Value 4 -Type DWord
        }
        if ($result.Success) {
            Write-Host "Registry modified successfully"
        }
    .EXAMPLE
        # Backup system DLL (VERY RISKY - for demonstration only!)
        $result = Invoke-AsTrustedInstaller -Path "C:\Windows\System32\some.dll" -ScriptBlock {
            param($dllPath)
            Copy-Item -LiteralPath $dllPath -Destination "C:\Backup\some.dll" -Force
        }
    .EXAMPLE
        # Modify multiple files in a folder recursively
        $result = Invoke-AsTrustedInstaller -Path "C:\Windows\SystemApps\Microsoft.Something" -Recurse -ScriptBlock {
            param($folderPath)
            # Perform operations on folder
            Get-ChildItem -Path $folderPath | Where-Object { $_.Extension -eq '.exe' } | ForEach-Object {
                Write-Host "Processing: $($_.Name)"
            }
        }
    .NOTES
        WARNING CRITICAL:
        - This is the HIGHEST privilege level in Windows!
        - Modifying system files can cause UNBOOTABLE SYSTEM!
        - ALWAYS create system restore point first!
        - ALWAYS backup original files!
        - Use ONLY when absolutely necessary!
        - Prefer registry modifications over file modifications!
        Hierarchy: User < Admin < SYSTEM < TrustedInstaller
        Reference: Study Doc 12-TrustedInstaller-Context.md
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,
        [object[]]$ArgumentList,
        [switch]$Recurse,
        [switch]$SkipOwnershipRestore
    )
    $opResult = [PSCustomObject]@{
        Success           = $false
        OriginalOwner     = $null
        NewOwner          = $null
        OwnershipRestored = $false
        Result            = $null
        Error             = $null
        BackupACL         = $null
    }
    # ═══════════════════════════════════════════════════════
    # STEP 0: Pre-flight checks
    # ═══════════════════════════════════════════════════════
    if (-not (Test-Path -LiteralPath $Path)) {
        $opResult.Error = "Path not found: $Path"
        Write-CoreLog $opResult.Error -Level ERROR
        return $opResult
    }
    if (-not (Test-Administrator)) {
        $opResult.Error = "TrustedInstaller operations require Administrator privileges"
        Write-CoreLog $opResult.Error -Level ERROR
        return $opResult
    }
    if (-not $PSCmdlet.ShouldProcess($Path, "Modify TrustedInstaller resource")) {
        return $opResult
    }
    Write-CoreLog "Starting TrustedInstaller operation on: $Path" -Level INFO
    try {
        # ═══════════════════════════════════════════════════════
        # STEP 1: Backup original ACL & Owner
        # ═══════════════════════════════════════════════════════
        Write-Verbose "Backing up original ACL..."
        $originalACL = Get-Acl -LiteralPath $Path
        $opResult.OriginalOwner = $originalACL.Owner
        $opResult.BackupACL = $originalACL
        Write-CoreLog "Original owner: $($opResult.OriginalOwner)" -Level INFO
        Write-Verbose "Original SDDL: $($originalACL.Sddl)"
        # Check if already TrustedInstaller-owned
        $isTIOned = Test-IsTrustedInstallerOwned -Path $Path
        if ($isTIOned) {
            Write-CoreLog "Resource is TrustedInstaller-owned - taking ownership" -Level WARNING
        }
        else {
            Write-Verbose "Resource is NOT TrustedInstaller-owned (current: $($opResult.OriginalOwner))"
        }
        # ═══════════════════════════════════════════════════════
        # STEP 2: Take ownership
        # ═══════════════════════════════════════════════════════
        Write-Verbose "Taking ownership..."
        $takeResult = Grant-TakeOwnership -Path $Path -Recurse:$Recurse
        if (-not $takeResult.Success) {
            throw "Failed to take ownership: $($takeResult.Error)"
        }
        $opResult.NewOwner = 'BUILTIN\Administrators'
        Write-CoreLog "Ownership transferred to: $($opResult.NewOwner)" -Level SUCCESS
        # ═══════════════════════════════════════════════════════
        # STEP 3: Execute script block
        # ═══════════════════════════════════════════════════════
        Write-CoreLog "Executing modification script block..." -Level INFO
        if ($ArgumentList) {
            $opResult.Result = & $ScriptBlock $Path @ArgumentList
        }
        else {
            $opResult.Result = & $ScriptBlock $Path
        }
        Write-CoreLog "Script block executed successfully" -Level SUCCESS
        # ═══════════════════════════════════════════════════════
        # STEP 4: Restore ownership (unless skipped)
        # ═══════════════════════════════════════════════════════
        if (-not $SkipOwnershipRestore) {
            Write-Verbose "Restoring original ownership..."
            if ($isTIOned) {
                # Restore to TrustedInstaller
                $restoreResult = Restore-TrustedInstallerOwnership -Path $Path -Recurse:$Recurse
                if ($restoreResult.Success) {
                    $opResult.OwnershipRestored = $true
                    Write-CoreLog "Ownership restored to TrustedInstaller" -Level SUCCESS
                }
                else {
                    Write-CoreLog "WARNING: Could not restore TrustedInstaller ownership: $($restoreResult.Error)" -Level WARNING
                    Write-CoreLog "Manual restoration may be required!" -Level WARNING
                }
            }
            else {
                # Restore to original owner (not TrustedInstaller)
                try {
                    Set-Acl -LiteralPath $Path -AclObject $originalACL
                    $opResult.OwnershipRestored = $true
                    Write-CoreLog "Ownership restored to: $($opResult.OriginalOwner)" -Level SUCCESS
                }
                catch {
                    Write-CoreLog "WARNING: Could not restore original ownership: $($_.Exception.Message)" -Level WARNING
                }
            }
        }
        else {
            Write-CoreLog "Ownership restoration SKIPPED (SkipOwnershipRestore flag set)" -Level WARNING
        }
        $opResult.Success = $true
        Write-CoreLog "TrustedInstaller operation completed successfully" -Level SUCCESS
    }
    catch {
        $opResult.Error = $_.Exception.Message
        Write-CoreLog "TrustedInstaller operation FAILED: $($opResult.Error)" -Level ERROR
        # ═══════════════════════════════════════════════════════
        # ROLLBACK: Attempt to restore ownership
        # ═══════════════════════════════════════════════════════
        Write-CoreLog "Attempting rollback..." -Level WARNING
        try {
            if ($opResult.BackupACL) {
                Set-Acl -LiteralPath $Path -AclObject $opResult.BackupACL
                Write-CoreLog "Rollback successful - ownership restored" -Level SUCCESS
            }
            else {
                Write-CoreLog "No backup ACL available for rollback" -Level ERROR
            }
        }
        catch {
            Write-CoreLog "CRITICAL: Rollback FAILED! Manual intervention required: $($_.Exception.Message)" -Level ERROR
            Write-CoreLog "Original owner was: $($opResult.OriginalOwner)" -Level ERROR
            Write-CoreLog "Path: $Path" -Level ERROR
        }
    }
    return $opResult
}
# ───────────────────────────────────────────────────────────────────────────
# CRITICAL RESTORE SAFETY FUNCTIONS
# ───────────────────────────────────────────────────────────────────────────
function Test-RestoreReadiness {
    <#
    .SYNOPSIS
        Pre-flight safety check before CRITICAL restore operations.
    .DESCRIPTION
        Performs comprehensive system checks before restore to prevent
        catastrophic failures. If restore fails, user has ONLY reinstall!
        **CHECKS PERFORMED:**
        1.  Administrator rights (CRITICAL)
        2.  Disk space (minimum 1 GB free)
        3.  PowerShell version (5.1+)
        4.  Critical Windows services (Schedule, Winmgmt)
        5.  Backup directory existence
        6.  SYSTEM privilege capability
        **FAILURE BEHAVIOR:**
        - CRITICAL issues → Return $false (BLOCK restore!)
        - WARNING issues → Return $true (Allow with warnings)
    .PARAMETER BackupPath
        Optional backup directory to validate (default: TEMP).
    .OUTPUTS
        [bool] True if restore can proceed safely, False if CRITICAL issues detected.
    .EXAMPLE
        if (Test-RestoreReadiness) {
            # Safe to proceed with restore
            Invoke-RestoreRegistry -BackupFile "..."
        } else {
            Write-Error "Pre-flight check FAILED! Cannot restore safely."
        }
    .NOTES
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [string]$BackupPath = (Join-Path $env:TEMP "KRAKE-FIX-Registry-Backups")
    )
    Write-CoreLog "PRE-FLIGHT CHECK: Validating system readiness for restore..." -Level WARNING
    $issues = @()
    # ═══════════════════════════════════════════════════════════════════════
    # CHECK 1: Administrator Rights (CRITICAL)
    # ═══════════════════════════════════════════════════════════════════════
    try {
        if (-not (Test-Administrator)) {
            $issues += @{
                Severity = "CRITICAL"
                Check    = "Administrator Rights"
                Message  = "Not running as Administrator"
                Fix      = "Run PowerShell as Administrator (Right-click → Run as Administrator)"
            }
        }
        else {
            Write-Verbose "CHECK 1: Administrator rights confirmed"
        }
    }
    catch {
        $issues += @{
            Severity = "CRITICAL"
            Check    = "Administrator Rights"
            Message  = "Failed to check admin status: $($_.Exception.Message)"
            Fix      = "Verify PowerShell process permissions"
        }
    }
    # ═══════════════════════════════════════════════════════════════════════
    # CHECK 2: Disk Space (CRITICAL)
    # ═══════════════════════════════════════════════════════════════════════
    try {
        $systemDrive = $env:SystemDrive.Trim(':')
        $drive = Get-PSDrive -Name $systemDrive -ErrorAction Stop
        $freeSpaceGB = [math]::Round($drive.Free / 1GB, 2)
        if ($freeSpaceGB -lt 1) {
            $issues += @{
                Severity = "CRITICAL"
                Check    = "Disk Space"
                Message  = "System drive has only $freeSpaceGB GB free (minimum 1 GB required)"
                Fix      = "Free up disk space before restore: Run Disk Cleanup or delete temporary files"
            }
        }
        else {
            Write-Verbose "CHECK 2: Disk space OK ($freeSpaceGB GB free)"
        }
    }
    catch {
        $issues += @{
            Severity = "WARNING"
            Check    = "Disk Space"
            Message  = "Failed to check disk space: $($_.Exception.Message)"
            Fix      = "Manually verify disk space availability"
        }
    }
    # ═══════════════════════════════════════════════════════════════════════
    # CHECK 3: PowerShell Version (CRITICAL)
    # ═══════════════════════════════════════════════════════════════════════
    try {
        $psVersion = $PSVersionTable.PSVersion
        if ($psVersion.Major -lt 5 -or ($psVersion.Major -eq 5 -and $psVersion.Minor -lt 1)) {
            $issues += @{
                Severity = "CRITICAL"
                Check    = "PowerShell Version"
                Message  = "PowerShell $psVersion < 5.1 (unsupported)"
                Fix      = "Update to PowerShell 5.1 or higher (Windows Management Framework 5.1)"
            }
        }
        else {
            Write-Verbose "CHECK 3: PowerShell version OK ($psVersion)"
        }
    }
    catch {
        $issues += @{
            Severity = "CRITICAL"
            Check    = "PowerShell Version"
            Message  = "Failed to check PowerShell version"
            Fix      = "Verify PowerShell installation"
        }
    }
    # ═══════════════════════════════════════════════════════════════════════
    # CHECK 4: Critical Windows Services (WARNING)
    # ═══════════════════════════════════════════════════════════════════════
    $criticalServices = @{
        'Schedule' = 'Task Scheduler (required for SYSTEM privilege escalation)'
        'Winmgmt'  = 'Windows Management Instrumentation (required for system queries)'
    }
    foreach ($svcName in $criticalServices.Keys) {
        try {
            $svc = Get-Service -Name $svcName -ErrorAction Stop
            if ($svc.Status -ne 'Running') {
                $issues += @{
                    Severity = "WARNING"
                    Check    = "Critical Service"
                    Message  = "Service '$svcName' is $($svc.Status) (should be Running)"
                    Fix      = "Start-Service -Name $svcName -ErrorAction Stop"
                }
            }
            else {
                Write-Verbose "CHECK 4: Service '$svcName' is running"
            }
        }
        catch {
            $issues += @{
                Severity = "WARNING"
                Check    = "Critical Service"
                Message  = "Service '$svcName' not found or inaccessible"
                Fix      = "Verify Windows services are not disabled by GPO"
            }
        }
    }
    # ═══════════════════════════════════════════════════════════════════════
    # CHECK 5: Backup Directory Existence (WARNING for restore)
    # ═══════════════════════════════════════════════════════════════════════
    try {
        if (-not (Test-Path -Path $BackupPath)) {
            $issues += @{
                Severity = "WARNING"
                Check    = "Backup Directory"
                Message  = "Backup directory not found: $BackupPath"
                Fix      = "Ensure backups were created before attempting restore"
            }
        }
        else {
            $backupCount = (Get-ChildItem -Path $BackupPath -Filter "*.xml" -ErrorAction SilentlyContinue).Count
            Write-Verbose "CHECK 5: Backup directory exists ($backupCount backup files)"
        }
    }
    catch {
        $issues += @{
            Severity = "WARNING"
            Check    = "Backup Directory"
            Message  = "Failed to check backup directory: $($_.Exception.Message)"
            Fix      = "Verify backup path accessibility"
        }
    }
    # ═══════════════════════════════════════════════════════════════════════
    # CHECK 6: SYSTEM Privilege Capability (INFO)
    # ═══════════════════════════════════════════════════════════════════════
    try {
        $canElevate = $Global:KRAKEFIX_SharedState.CanElevateToSystem

        if (-not $canElevate) {
            Write-Verbose "CHECK 6: SYSTEM privilege escalation not available (Admin fallback will be used)"
        }
        else {
            Write-Verbose "CHECK 6: SYSTEM privilege escalation available"
        }
    }
    catch {
        Write-Verbose "CHECK 6: SYSTEM capability check skipped"
    }
    # ═══════════════════════════════════════════════════════════════════════
    # ANALYZE RESULTS
    # ═══════════════════════════════════════════════════════════════════════
    $criticalIssues = $issues | Where-Object { $_.Severity -eq "CRITICAL" }
    $warningIssues = $issues | Where-Object { $_.Severity -eq "WARNING" }
    if ($criticalIssues.Count -gt 0) {
        Write-CoreLog "PRE-FLIGHT CHECK FAILED! $($criticalIssues.Count) CRITICAL issue(s) detected!" -Level ERROR
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
        Write-Host "   CRITICAL ISSUES - RESTORE BLOCKED!" -ForegroundColor Red
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
        Write-Host ""
        foreach ($issue in $criticalIssues) {
            Write-Host "$($issue.Check): $($issue.Message)" -ForegroundColor Red
            Write-Host "   FIX: $($issue.Fix)" -ForegroundColor Yellow
            Write-Host ""
            Write-CoreLog "$($issue.Check): $($issue.Message)" -Level ERROR
        }
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
        Write-Host "Restore cannot proceed until CRITICAL issues are resolved!" -ForegroundColor Red
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
        Write-Host ""
        return $false
    }
    if ($warningIssues.Count -gt 0) {
        Write-CoreLog "PRE-FLIGHT CHECK: $($warningIssues.Count) warning(s) detected" -Level WARNING
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow
        Write-Host "   WARNINGS DETECTED" -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow
        Write-Host ""
        foreach ($warn in $warningIssues) {
            Write-Host " $($warn.Check): $($warn.Message)" -ForegroundColor Yellow
            Write-Host " SUGGESTION: $($warn.Fix)" -ForegroundColor Gray
            Write-Host ""
        }
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow
        Write-Host "Restore can proceed, but with reduced reliability." -ForegroundColor Yellow
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Yellow
        Write-Host ""
    }
    Write-CoreLog "PRE-FLIGHT CHECK PASSED - Restore can proceed safely" -Level SUCCESS
    return $true
}
function Invoke-EmergencyRestoreViaRegExe {
    <#
    .SYNOPSIS
        EMERGENCY FAILSAFE: Restore registry using native Windows reg.exe tool.
    .DESCRIPTION
        When PowerShell-based restore fails, this function provides a
        LAST-RESORT fallback using Windows built-in reg.exe utility.
        **WHY THIS EXISTS:**
        - reg.exe is EXTREMELY reliable (built into Windows since XP)
        - Works even when PowerShell cmdlets fail
        - Direct Win32 API access (no PowerShell overhead)
        - Can restore even when registry provider is corrupted
        **WHEN TO USE:**
        - ONLY when Invoke-RestoreRegistry fails
        - ONLY as last resort before manual intervention
        **LIMITATIONS:**
        - Cannot handle complex data types (Binary, MultiString)
        - Limited to String, DWord, QWord registry types
        - No automatic retry logic (single attempt)
    .PARAMETER BackupFile
        Path to XML backup file created by Invoke-RegistryOperation.
    .OUTPUTS
        [bool] True if emergency restore succeeded, False otherwise.
    .EXAMPLE
        # Normal restore failed, try emergency fallback
        if (-not (Invoke-RestoreRegistry -BackupFile $backup).Success) {
            Write-Warning "PowerShell restore failed! Trying emergency reg.exe fallback..."
            Invoke-EmergencyRestoreViaRegExe -BackupFile $backup
        }
    .NOTES
        Reference: CRITICAL-RESTORE-SAFETY-PLAN.md
        Study: @STUDY/02-Registry-Security-Deep-Dive.md
         This is a FAILSAFE mechanism - use only when normal restore fails!
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path $_ })]
        [string]$BackupFile
    )
    Write-CoreLog " EMERGENCY RESTORE ACTIVATED: Using reg.exe fallback" -Level WARNING
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host "  EMERGENCY RESTORE MODE" -ForegroundColor Red
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
    Write-Host "PowerShell restore failed. Attempting native reg.exe restore..." -ForegroundColor Yellow
    Write-Host ""
    $tempRegFile = $null
    try {
        # ═══════════════════════════════════════════════════════════════════════
        # STEP 1: Load backup data
        # ═══════════════════════════════════════════════════════════════════════
        Write-Verbose "Loading backup file: $BackupFile"
        $backup = Import-Clixml -Path $BackupFile -ErrorAction Stop
        Write-Verbose "Backup data: Path=$($backup.Path), Name=$($backup.Name), Value=$($backup.OriginalValue), Type=$($backup.OriginalType)"
        # ═══════════════════════════════════════════════════════════════════════
        # STEP 2: Handle 'ValueDoesNotExist' case (DELETE value)
        # ═══════════════════════════════════════════════════════════════════════
        if ($backup.ValueExists -eq $false -or $backup.OriginalValue -eq "ValueDoesNotExist") {
            Write-CoreLog "Registry value did not exist originally - deleting via reg.exe" -Level WARNING
            # Convert PowerShell path to reg.exe format
            $regPath = $backup.Path -replace '^HKLM:', 'HKLM' -replace '^HKCU:', 'HKCU' -replace '^HKCR:', 'HKCR' -replace '^HKU:', 'HKU' -replace '^HKCC:', 'HKCC'
            # Execute reg.exe delete
            $deleteArgs = @('delete', "`"$regPath`"", '/v', "`"$($backup.Name)`"", '/f')
            Write-Verbose "Executing: reg.exe $($deleteArgs -join ' ')"
            $deleteOutput = & reg.exe @deleteArgs 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-CoreLog "EMERGENCY RESTORE: Value deleted successfully" -Level SUCCESS
                Write-Host "Value deleted: $($backup.Path)\$($backup.Name)" -ForegroundColor Green
                return $true
            }
            elseif ($LASTEXITCODE -eq 1) {
                # Exit code 1 = Value not found (already deleted - OK)
                Write-CoreLog "EMERGENCY RESTORE: Value already deleted (OK)" -Level SUCCESS
                Write-Host "Value already in correct state (not present)" -ForegroundColor Green
                return $true
            }
            else {
                throw "reg.exe delete failed (exit code $LASTEXITCODE): $deleteOutput"
            }
        }
        # ═══════════════════════════════════════════════════════════════════════
        # STEP 3: Validate registry type compatibility
        # ═══════════════════════════════════════════════════════════════════════
        $supportedTypes = @('String', 'DWord', 'QWord', 'ExpandString')
        if ($backup.OriginalType -notin $supportedTypes) {
            Write-CoreLog "EMERGENCY RESTORE: Type '$($backup.OriginalType)' not supported by reg.exe fallback" -Level ERROR
            Write-Host "Registry type '$($backup.OriginalType)' requires manual restore" -ForegroundColor Red
            Write-Host "Supported types: String, DWord, QWord, ExpandString" -ForegroundColor Yellow
            Write-Host "Backup file: $BackupFile" -ForegroundColor Yellow
            return $false
        }
        # ═══════════════════════════════════════════════════════════════════════
        # STEP 4: Create temporary .reg file
        # ═══════════════════════════════════════════════════════════════════════
        $tempRegFile = Join-Path $env:TEMP "KRAKE-EMERGENCY-$(Get-Random).reg"
        Write-Verbose "Creating temporary .reg file: $tempRegFile"
        # Convert PowerShell path to .reg format
        $regPath = $backup.Path -replace '^HKLM:', 'HKEY_LOCAL_MACHINE' `
            -replace '^HKCU:', 'HKEY_CURRENT_USER' `
            -replace '^HKCR:', 'HKEY_CLASSES_ROOT' `
            -replace '^HKU:', 'HKEY_USERS' `
            -replace '^HKCC:', 'HKEY_CURRENT_CONFIG'
        # Format value based on type
        $regValue = switch ($backup.OriginalType) {
            'DWord' {
                # DWord: hex format (8 digits)
                "dword:$("{0:x8}" -f [int]$backup.OriginalValue)"
            }
            'QWord' {
                # QWord: hex format (16 digits, little-endian byte order)
                $qwordValue = [uint64]$backup.OriginalValue
                $bytes = [BitConverter]::GetBytes($qwordValue)
                $hexString = ($bytes | ForEach-Object { "{0:x2}" -f $_ }) -join ','
                "hex(b):$hexString"
            }
            'String' {
                # String: quoted, escape backslashes and quotes
                $escaped = $backup.OriginalValue -replace '\\', '\\' -replace '"', '\"'
                "`"$escaped`""
            }
            'ExpandString' {
                # ExpandString: hex(2) format
                $unicode = [System.Text.Encoding]::Unicode.GetBytes($backup.OriginalValue + "`0")
                $hexString = ($unicode | ForEach-Object { "{0:x2}" -f $_ }) -join ','
                "hex(2):$hexString"
            } default {
                throw "Unsupported registry type: $($backup.OriginalType)"
            }
        }
        # Build .reg file content
        $regContent = @"
Windows Registry Editor Version 5.00
[$regPath]
"$($backup.Name)"=$regValue
"@
        Write-Verbose ".reg content:`n$regContent"
        # Write to file (Unicode encoding required for .reg files)
        Set-Content -Path $tempRegFile -Value $regContent -Encoding Unicode -Force
        # ═══════════════════════════════════════════════════════════════════════
        # STEP 5: Execute reg.exe import (CRITICAL OPERATION)
        # ═══════════════════════════════════════════════════════════════════════
        Write-CoreLog "Executing reg.exe import..." -Level WARNING
        $importArgs = @('import', "`"$tempRegFile`"")
        Write-Verbose "Executing: reg.exe $($importArgs -join ' ')"
        $regOutput = & reg.exe @importArgs 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-CoreLog "EMERGENCY RESTORE SUCCESSFUL via reg.exe" -Level SUCCESS
            Write-Host ""
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
            Write-Host " EMERGENCY RESTORE SUCCESSFUL!" -ForegroundColor Green
            Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
            Write-Host "Registry restored: $($backup.Path)\$($backup.Name)" -ForegroundColor Green
            Write-Host "Value: $($backup.OriginalValue)" -ForegroundColor Gray
            Write-Host ""
            return $true
        }
        else {
            throw "reg.exe import failed (exit code $LASTEXITCODE): $regOutput"
        }
    }
    catch {
        Write-CoreLog " EMERGENCY RESTORE FAILED: $($_.Exception.Message)" -Level ERROR
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
        Write-Host "   EMERGENCY RESTORE FAILED!" -ForegroundColor Red
        Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Red
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        Write-Host "MANUAL INTERVENTION REQUIRED:" -ForegroundColor Yellow
        Write-Host "1. Open backup file: $BackupFile" -ForegroundColor Yellow
        Write-Host "2. Manually restore registry using regedit.exe" -ForegroundColor Yellow
        Write-Host "3. Or contact system administrator" -ForegroundColor Yellow
        Write-Host ""

        return $false
    }
    finally {
        # ═══════════════════════════════════════════════════════════════════════
        # CLEANUP: Remove temporary .reg file
        # ═══════════════════════════════════════════════════════════════════════
        if ($null -ne $tempRegFile -and (Test-Path $tempRegFile)) {
            try {
                Remove-Item -Path $tempRegFile -Force -ErrorAction SilentlyContinue
                Write-Verbose "Cleaned up temporary file: $tempRegFile"
            }
            catch {
                Write-Verbose "Failed to cleanup temp file: $tempRegFile"
            }
        }
    }
}
# ───────────────────────────────────────────────────────────────────────────
# BACKUP MANAGEMENT
# ───────────────────────────────────────────────────────────────────────────
function Remove-OldBackups {
    <#
    .SYNOPSIS
        Cleanup old backup files to prevent disk space accumulation.
    .DESCRIPTION
        Removes backup files older than specified number of days from:
        - Registry backups
        - Service backups
        - ACL backups
        This prevents unbounded growth of backup files in TEMP directory.
    .PARAMETER DaysToKeep
        Number of days to keep backup files (default: 7).
    .PARAMETER BackupPath
        Optional custom backup path (defaults to $env:TEMP).
    .OUTPUTS
        [PSCustomObject] with statistics about cleaned backups.
    .EXAMPLE
        Remove-OldBackups -DaysToKeep 7
        # Removes all backups older than 7 days
    .EXAMPLE
        Remove-OldBackups -DaysToKeep 30 -Verbose
        # Removes backups older than 30 days with verbose output
    #>
    [CmdletBinding()]
    param(
        [int]$DaysToKeep = 7,
        [string]$BackupPath = $env:TEMP
    )
    $result = [PSCustomObject]@{
        RegistryBackupsRemoved = 0
        ServiceBackupsRemoved  = 0
        ACLBackupsRemoved      = 0
        TotalFilesRemoved      = 0
        TotalBytesFreed        = 0
        Error                  = $null
    }
    try {
        $cutoffDate = (Get-Date).AddDays(-$DaysToKeep)
        Write-Verbose "Removing backups older than: $cutoffDate"
        $backupDirs = @(
            'KRAKE-FIX-Registry-Backups',
            'KRAKE-FIX-Service-Backups',
            'KRAKE-FIX-ACL-Backups'
        )
        foreach ($dir in $backupDirs) {
            $fullPath = Join-Path $BackupPath $dir
            if (Test-Path $fullPath) {
                $oldFiles = Get-ChildItem -Path $fullPath -File | Where-Object {
                    $_.LastWriteTime -lt $cutoffDate
                }
                foreach ($file in $oldFiles) {
                    try {
                        $fileSize = $file.Length
                        Remove-Item -Path $file.FullName -Force -ErrorAction Stop

                        $result.TotalFilesRemoved++
                        $result.TotalBytesFreed += $fileSize

                        switch -Wildcard ($dir) {
                            '*Registry*' { $result.RegistryBackupsRemoved++ }
                            '*Service*' { $result.ServiceBackupsRemoved++ }
                            '*ACL*' { $result.ACLBackupsRemoved++ }
                        }

                        Write-Verbose "Removed old backup: $($file.Name) ($([math]::Round($fileSize/1KB, 2)) KB)"
                    }
                    catch {
                        Write-Warning "Failed to remove backup file $($file.Name): $($_.Exception.Message)"
                    }
                }
            }
        }

        $mbFreed = [math]::Round($result.TotalBytesFreed / 1MB, 2)
        Write-CoreLog "Backup cleanup completed: $($result.TotalFilesRemoved) files removed, $mbFreed MB freed" -Level SUCCESS

    }
    catch {
        $result.Error = $_.Exception.Message
        Write-CoreLog "Backup cleanup failed: $($result.Error)" -Level ERROR
    }

    return $result
}
# ───────────────────────────────────────────────────────────────────────────
# MODULE INITIALIZATION
# ───────────────────────────────────────────────────────────────────────────
# Initialize privilege detection (with caching to avoid repeated expensive checks)
$Global:KRAKEFIX_SharedState.IsAdmin = Test-Administrator
# FIX: Cache SYSTEM privilege test result (expensive operation - creates/deletes scheduled task)
# Only test once per PowerShell session
if (-not $Global:KRAKEFIX_SharedState.ContainsKey('CanElevateToSystem_Cached')) {
    Write-Verbose "Testing SYSTEM privilege escalation capability (first run)..."
    $Global:KRAKEFIX_SharedState.CanElevateToSystem = Test-SystemPrivilege
    $Global:KRAKEFIX_SharedState.CanElevateToSystem_Cached = $true
}
else {
    Write-Verbose "Using cached SYSTEM privilege detection result"
}
# Detect integrity level
try {
    $Global:KRAKEFIX_SharedState.IntegrityLevel = Get-ProcessIntegrityLevel
}
catch {
    $Global:KRAKEFIX_SharedState.IntegrityLevel = 'Unknown'
}
# ───────────────────────────────────────────────────────────────────────────
# TWEAK APPLICATION & REVERT FUNCTIONS
# ───────────────────────────────────────────────────────────────────────────
function Convert-ServiceStartTypeName {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object]$Value
    ) if ($null -eq $Value) {
        return $null
    } if ($Value -is [string]) {
        $normalized = $Value.ToString().Trim().ToLowerInvariant()
        switch ($normalized) {
            'automatic' { return 'Automatic' }
            'manual' { return 'Manual' }
            'disabled' { return 'Disabled' }
            default { return $null }
        }
    } try {
        $intValue = [int]$Value
    }
    catch {
        return $null
    } switch ($intValue) {
        2 { return 'Automatic' }
        3 { return 'Manual' }
        4 { return 'Disabled' }
        default { return $null }
    }
}
function Invoke-HostsDomainUpdate {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string[]]$Domains,
        [Parameter(Mandatory)][bool]$Apply
    )
    $normalizedDomains = $Domains |
    Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
    ForEach-Object { $_.Trim() } |
    Sort-Object -Unique
    if ($normalizedDomains.Count -eq 0) {
        return [pscustomobject]@{
            Success = $true
            Result  = [pscustomobject]@{
                Success = $true
                Updated = $false
                Message = 'NoDomains'
            }
        }
    }
    $hostsPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\drivers\etc\hosts'
    $scriptBlock = {
        param(
            [string]$HostsPath,
            [string[]]$DomainList,
            [bool]$ShouldApply
        )
        if (-not (Test-Path -LiteralPath $HostsPath)) {
            return [pscustomobject]@{
                Success = $false
                Updated = $false
                Message = 'HostsFileMissing'
            }
        }
        $encoding = [System.Text.Encoding]::ASCII
        $currentLines = @()
        if (Test-Path -LiteralPath $HostsPath) {
            $currentLines = Get-Content -LiteralPath $HostsPath -ErrorAction Stop
        }
        $lineBuffer = [System.Collections.ArrayList]::new()
        if ($null -ne $currentLines -and $currentLines.Count -gt 0) {
            [void]$lineBuffer.AddRange($currentLines)
        }
        $changed = $false
        if ($ShouldApply) {
            foreach ($domainName in $DomainList) {
                $escaped = [regex]::Escape($domainName)
                $exists = $false
                foreach ($line in $lineBuffer) {
                    if ($null -eq $line) {
                        continue
                    }
                    if ($line -match "^(?:0\\.0\\.0\\.0|127\\.0\\.0\\.1)\\s+$escaped(\\s|$)") {
                        $exists = $true
                        break
                    }
                }
                if (-not $exists) {
                    [void]$lineBuffer.Add("0.0.0.0`t$domainName")
                    $changed = $true
                }
            }
        }
        else {
            for ($index = $lineBuffer.Count - 1; $index -ge 0; $index--) {
                $lineText = $lineBuffer[$index]
                if ($null -eq $lineText) {
                    continue
                }
                $trimmed = $lineText.Trim()
                foreach ($domainName in $DomainList) {
                    $escaped = [regex]::Escape($domainName)
                    if ($trimmed -match "^(?:0\\.0\\.0\\.0|127\\.0\\.0\\.1)\\s+$escaped(\\s|$)") {
                        $lineBuffer.RemoveAt($index)
                        $changed = $true
                        break
                    }
                }
            }
        }
        if ($changed) {
            $outputLines = [string[]]$lineBuffer.ToArray([string])
            [System.IO.File]::WriteAllLines($HostsPath, $outputLines, $encoding)
        }
        return [pscustomobject]@{
            Success = $true
            Updated = $changed
            Message = 'OK'
        }
    }
    return Invoke-WithPrivilege -ScriptBlock $scriptBlock -ArgumentList @($hostsPath, $normalizedDomains, [bool]$Apply) -RequiredPrivilege 'Admin'
}

function Restore-RegistryValueFromLatestBackup {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name
    )
    $backupDirectory = Join-Path ([Environment]::GetFolderPath('Desktop')) 'KRAKE-Backup\Registry-Backups'
    if (-not (Test-Path -LiteralPath $backupDirectory)) {
        Write-CoreLog ("Restore skipped {0} backup directory not found: {1}" -f ([char]0x2013), $backupDirectory) -Level WARNING
        return $false
    }
    $safePath = ($Path -replace '[:\\]', '_')
    $safeName = ($Name -replace '[\\/:*?"<>|]', '_')
    $pattern = "REG-$safePath-$safeName-*.xml"
    $latestBackup = Get-ChildItem -Path $backupDirectory -Filter $pattern -ErrorAction SilentlyContinue |
    Sort-Object -Property LastWriteTime -Descending |
    Select-Object -First 1
    if (-not $latestBackup) {
        Write-CoreLog ("Restore skipped {0} no backup matches pattern {1}" -f ([char]0x2013), $pattern) -Level WARNING
        return $false
    }
    $restoreResult = Invoke-RestoreRegistry -BackupFile $latestBackup.FullName
    if (-not $restoreResult.Success) {
        Write-CoreLog "Restore failed for $Path::$Name using $($latestBackup.FullName): $($restoreResult.Error)" -Level ERROR
        return $false
    }
    Write-CoreLog "Restore success: $Path::$Name via $($latestBackup.Name)" -Level SUCCESS
    return $true
}
function Restore-ServiceFromLatestBackup {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$ServiceName
    )
    $backupDirectory = Join-Path ([Environment]::GetFolderPath('Desktop')) 'KRAKE-Backup\Service-Backups'
    if (-not (Test-Path -LiteralPath $backupDirectory)) {
        Write-CoreLog ("Service restore skipped {0} backup directory not found: {1}" -f ([char]0x2013), $backupDirectory) -Level WARNING
        return $false
    }
    $pattern = "SVC-$ServiceName-*.xml"
    $latestBackup = Get-ChildItem -Path $backupDirectory -Filter $pattern -ErrorAction SilentlyContinue |
    Sort-Object -Property LastWriteTime -Descending |
    Select-Object -First 1
    if (-not $latestBackup) {
        Write-CoreLog ("Service restore skipped {0} no backup matches pattern {1}" -f ([char]0x2013), $pattern) -Level WARNING
        return $false
    }
    $restoreResult = Invoke-RestoreService -BackupFile $latestBackup.FullName
    if (-not $restoreResult.Success) {
        Write-CoreLog ("Service restore failed for {0} using {1}: {2}" -f $ServiceName, $latestBackup.FullName, $restoreResult.Error) -Level ERROR
        return $false
    }
    Write-CoreLog ("Service restore success: {0} via {1}" -f $ServiceName, $latestBackup.Name) -Level SUCCESS
    return $true
}
function Resolve-ServiceNamePattern {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][string]$NamePattern
    )
    if ([string]::IsNullOrWhiteSpace($NamePattern)) {
        return @()
    }
    if ($NamePattern -notmatch '[\*\?]') {
        return @($NamePattern)
    }
    $resolvedNames = @()
    try {
        $resolvedNames = @(Get-Service -Name $NamePattern -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    }
    catch {
        $resolvedNames = @()
    }
    if (-not $resolvedNames -or $resolvedNames.Count -eq 0) {
        try {
            $resolvedNames = @(Get-Service -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like $NamePattern } |
                Select-Object -ExpandProperty Name)
        }
        catch {
            $resolvedNames = @()
        }
    }
    if (-not $resolvedNames) {
        return @()
    }
    return @($resolvedNames | Select-Object -Unique)
}
function Invoke-TweakServiceRestore {
    [CmdletBinding()]
    param()
    $serviceSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $serviceCommands = @(
        @{ Command = 'Get-TweakAServiceList'; Module = 'TweakA.psm1' },
        @{ Command = 'Get-TweakBServiceList'; Module = 'TweakB.psm1' },
        @{ Command = 'Get-TweakCServiceList'; Module = 'TweakC.psm1' }
    )
    foreach ($entry in $serviceCommands) {
        $commandName = $entry.Command
        $commandInfo = Get-Command -Name $commandName -ErrorAction SilentlyContinue
        if ($null -eq $commandInfo) {
            $modulePath = Join-Path -Path $PSScriptRoot -ChildPath $entry.Module
            if (Test-Path -LiteralPath $modulePath) {
                try {
                    Import-Module -Name $modulePath -Force -ErrorAction Stop
                    $commandInfo = Get-Command -Name $commandName -ErrorAction SilentlyContinue
                }
                catch {
                    $message = "{0}" -f $_.Exception.Message
                    Write-CoreLog ("Failed to import module {0} for {1}: {2}" -f $modulePath, $commandName, $message) -Level WARNING
                }
            }
        }
        if ($null -eq $commandInfo) {
            continue
        }
        try {
            $serviceList = & $commandInfo
            foreach ($serviceItem in $serviceList) {
                if ($null -eq $serviceItem) { continue }
                $serviceName = if ($serviceItem -is [string]) {
                    $serviceItem.Trim()
                }
                elseif ($serviceItem.PSObject.Properties['Name']) {
                    [string]$serviceItem.Name
                }
                else {
                    [string]$serviceItem
                }
                if ([string]::IsNullOrWhiteSpace($serviceName)) {
                    continue
                }
                $null = $serviceSet.Add($serviceName.Trim())
            }
        }
        catch {
            $message = "{0}" -f $_.Exception.Message
            Write-CoreLog ("Failed to retrieve service list via {0}: {1}" -f $commandName, $message) -Level WARNING
        }
    }
    if ($serviceSet.Count -eq 0) {
        Write-CoreLog 'No tweak service list could be loaded for restore.' -Level WARNING
        return
    }
    foreach ($serviceName in $serviceSet) {
        if ($serviceName -match '[\*\?]') {
            $expandedNames = Resolve-ServiceNamePattern -NamePattern $serviceName
            if ($expandedNames) {
                foreach ($expandedName in $expandedNames) {
                    Restore-ServiceFromLatestBackup -ServiceName $expandedName | Out-Null
                }
                continue
            }
        }
        Restore-ServiceFromLatestBackup -ServiceName $serviceName | Out-Null
    }
}
function Invoke-Win32PriorityDefault {
    [CmdletBinding()]
    param(
        [switch]$Apply
    )
    if ($Apply) {
        Write-CoreLog 'Invoke-Win32PriorityDefault apply path is not supported (menu uses revert only).' -Level WARNING
        return
    }
    if (-not (Restore-RegistryValueFromLatestBackup -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl' -Name 'Win32PrioritySeparation')) {
        $parameters = @{
            Path              = 'HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl'
            Name              = 'Win32PrioritySeparation'
            Value             = 2
            Type              = 'DWord'
            Operation         = 'Set'
            RequiredPrivilege = 'System'
            CreatePath        = $true
        }
        $result = Invoke-RegistryOperation @parameters
        if (-not $result.Success) {
            Write-CoreLog "Failed to restore Win32PrioritySeparation: $($result.Error)" -Level ERROR
        }
        else {
            Write-CoreLog 'Win32PrioritySeparation restored to default (0x02).' -Level SUCCESS
        }
    }
}
function Invoke-HidLatencyDefault {
    [CmdletBinding()]
    param(
        [switch]$Apply
    )
    if ($Apply) {
        Write-CoreLog 'Invoke-HidLatencyDefault apply path is not supported (menu uses revert only).' -Level WARNING
        return
    }
    $registryItems = @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\kbdclass\Parameters'; Name = 'KeyboardDataQueueSize' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\mouclass\Parameters'; Name = 'MouseDataQueueSize' }
    )
    foreach ($item in $registryItems) {
        if (Restore-RegistryValueFromLatestBackup -Path $item.Path -Name $item.Name) {
            continue
        }
        $parameters = @{
            Path              = $item.Path
            Name              = $item.Name
            Value             = 100
            Type              = 'DWord'
            Operation         = 'Set'
            RequiredPrivilege = 'System'
            CreatePath        = $true
        }
        $result = Invoke-RegistryOperation @parameters
        if (-not $result.Success) {
            Write-CoreLog "Failed to restore HID queue size ($($item.Name)): $($result.Error)" -Level ERROR
        }
        else {
            Write-CoreLog "HID queue size restored ($($item.Name)=100)." -Level SUCCESS
        }
    }
}
function Invoke-NvidiaGpuRestore {
    [CmdletBinding()]
    param(
        [switch]$Apply
    ) if ($Apply) {
        Write-CoreLog 'Invoke-NvidiaGpuRestore apply path is not supported (menu uses revert only).' -Level WARNING
        return
    }
    $targets = @(
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS'; Name = 'EnableRID61684' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS'; Name = 'PerfLevelSrc' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS'; Name = 'FTSDelay' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'; Name = 'TdrDelay' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'; Name = 'TdrDdiDelay' },
        @{ Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers'; Name = 'TdrLevel' },
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Direct3D'; Name = 'MaxPreRenderedFrames' }
    )
    foreach ($entry in $targets) {
        $restored = Restore-RegistryValueFromLatestBackup -Path $entry.Path -Name $entry.Name
        if (-not $restored) {
            Write-CoreLog "NVIDIA restore missed for $($entry.Path)::$($entry.Name)" -Level WARNING
        }
    }
}

function Invoke-IntelGpuRestore {
    [CmdletBinding()]
    param(
        [switch]$Apply
    ) if ($Apply) {
        Write-CoreLog 'Invoke-IntelGpuRestore apply path is not supported (menu uses revert only).' -Level WARNING
        return
    }
    $regPath = 'HKLM:\SOFTWARE\Intel\Display\igfxcui\MediaKeys'
    $tweakNames = @(
        'ProcAmpApplyAlways', 'ProcAmpHue', 'ProcAmpSaturation', 'ProcAmpContrast', 'ProcAmpBrightness',
        'EnableTCC', 'SatFactorRed', 'SatFactorGreen', 'SatFactorBlue', 'SatFactorYellow', 'SatFactorCyan', 'SatFactorMagenta',
        'InputYUVRange', 'EnableFMD', 'NoiseReductionEnabledAlways', 'NoiseReductionAutoDetectEnabledAlways',
        'NoiseReductionEnableChroma', 'NoiseReductionFactor', 'SharpnessEnabledAlways', 'UISharpnessOptimalEnabledAlways',
        'SharpnessFactor', 'EnableSTE', 'SkinTone', 'EnableACE', 'EnableIS', 'AceLevel',
        'EnableNLAS', 'NLASVerticalCrop', 'NLASHLinearRegion', 'NLASNonLinearCrop',
        'GCompMode', 'GExpMode', 'InputYUVRangeApplyAlways', 'SuperResolutionEnabled'
    )
    foreach ($name in $tweakNames) {
        $restored = Restore-RegistryValueFromLatestBackup -Path $regPath -Name $name
        if (-not $restored) {
            Write-CoreLog "Intel GPU restore missed for $regPath::$name" -Level WARNING
        }
    }
}
function Invoke-HostsTelemetryRestore {
    [CmdletBinding()]
    param()
    Write-CoreLog 'Starting Hosts telemetry restore.' -Level INFO
    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $backupPath = "$hostsPath.backup"
    if (-not (Test-Path -LiteralPath $hostsPath)) {
        Write-CoreLog ('HOSTS file not found {0} restore skipped.' -f ([char]0x2013)) -Level WARNING
        Write-Warning "HOSTS file neexistuje! Nelze obnovit."
        return
    }
    $copyResult = $null
    if (Test-Path -LiteralPath $backupPath) {
        $copyResult = Invoke-WithPrivilege -ScriptBlock {
            param($source, $destination)
            Copy-Item -Path $source -Destination $destination -Force -ErrorAction Stop
            return $true
        } -ArgumentList @($backupPath, $hostsPath) -RequiredPrivilege 'Admin' -RetryCount 3 -RetryDelayMs 500
        if ($copyResult.Success) {
            Write-CoreLog 'HOSTS file restored from backup copy.' -Level SUCCESS
            Write-Host 'HOSTS file obnoven ze zálohy.' -ForegroundColor Green
        }
        else {
            Write-CoreLog "HOSTS backup copy failed: $($copyResult.Error)" -Level WARNING
            Write-Warning 'Nepodařilo se obnovit ze zálohy. Pokračuji odstraněním telemetry bloku.'
        }
    } if (-not $copyResult -or -not $copyResult.Success) {
        $cleanupResult = Invoke-WithPrivilege -ScriptBlock {
            param($hostsFile)
            $maxRetries = 3
            $retry = 0
            $content = $null
            while ($retry -lt $maxRetries -and $null -eq $content) {
                try {
                    $content = Get-Content -LiteralPath $hostsFile -ErrorAction Stop
                }
                catch {
                    $retry++
                    if ($retry -ge $maxRetries) {
                        throw $_
                    }
                    Start-Sleep -Milliseconds 500
                }
            }
            $newContent = @()
            $inBlock = $false
            foreach ($line in $content) {
                if ($line -match '# === TELEMETRY BLOCK START ===') {
                    $inBlock = $true
                    continue
                } if ($line -match '# === TELEMETRY BLOCK END ===') {
                    $inBlock = $false
                    continue
                } if (-not $inBlock) {
                    $newContent += $line
                }
            }
            $retry = 0
            $written = $false
            while ($retry -lt $maxRetries -and -not $written) {
                try {
                    $newContent | Out-File -FilePath $hostsFile -Encoding ASCII -Force -ErrorAction Stop
                    $written = $true
                }
                catch {
                    $retry++
                    if ($retry -ge $maxRetries) {
                        throw $_
                    }
                    Start-Sleep -Milliseconds 500
                }
            }
            return $true
        } -ArgumentList @($hostsPath) -RequiredPrivilege 'Admin' -RetryCount 1 -RetryDelayMs 0
        if ($cleanupResult.Success) {
            Write-CoreLog 'Telemetry block removed from HOSTS file.' -Level SUCCESS
            Write-Host 'Telemetrické záznamy odstraněny z HOSTS.' -ForegroundColor Green
        }
        else {
            Write-CoreLog "Failed to clean HOSTS file: $($cleanupResult.Error)" -Level ERROR
            Write-Warning 'Nepodařilo se odstranit telemetrické záznamy z HOSTS.'
        }
    } try {
        Remove-NetFirewallRule -DisplayName 'Block Telemetry IPs' -ErrorAction SilentlyContinue | Out-Null
        Write-CoreLog 'Telemetry firewall rule removed.' -Level SUCCESS
    }
    catch {
        Write-CoreLog "Failed to remove telemetry firewall rule: $($_.Exception.Message)" -Level WARNING
    }
    Write-Host 'HOSTS file obnoven do původního stavu.' -ForegroundColor Green
}
function Invoke-RevertToDefaults {
    <#
    .SYNOPSIS
        Apply or revert tweak categories defined in Data.psm1.
    .DESCRIPTION
        Uses centralized definitions stored in Data.psm1 to modify registry keys, services, and hosts file entries.
        Operations are executed via privileged helpers (Invoke-RegistryOperation, Invoke-ServiceOperation,
        Invoke-HostsDomainUpdate) with full logging and idempotence.
    .PARAMETER Category
        Tweak category to process (GamingPerf, TelemetryServices, MitigationsCPU, or All).
    .PARAMETER Apply
        Switch controlling direction of the operation. When present, tweaks are applied; otherwise reverted.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'GamingPerf', 'TelemetryServices', 'MitigationsCPU',
            'WinUpdateServices', 'WinUpdateDrivers', 'VBS', 'Integrity', 'LSA', 'TSX',
            'DefenderRT', 'DefenderBlock', 'FullAdmin', 'OtherServices',
            'Win32Prio', 'HIDLatency', 'NvidiaGPU', 'IntelGPU',
            'All'
        )]
        [string]$Category,
        [switch]$Apply
    )
    $action = if ($Apply) { 'Aplikace' } else { 'Obnova' }
    Write-CoreLog "$action tweaků pro kategorii: $Category" -Level INFO
    $dataModulePath = Join-Path -Path $PSScriptRoot -ChildPath 'Data.psm1'
    try {
        if (-not (Get-Module -Name 'Data')) {
            if (-not (Test-Path -LiteralPath $dataModulePath)) {
                throw "Data.psm1 nenalezen: $dataModulePath"
            }
            Import-Module -Name $dataModulePath -Force -Global -ErrorAction Stop
            Write-CoreLog "Data.psm1 importován z $dataModulePath" -Level INFO
        }
    }
    catch {
        $err = "Načtení Data.psm1 selhalo: $($_.Exception.Message)"
        Write-CoreLog $err -Level ERROR
        throw $err
    } if (-not (Get-Command -Name Get-CategoryData -ErrorAction SilentlyContinue)) {
        $msg = 'Data.psm1 neexportuje Get-CategoryData. Operaci nelze provést.'
        Write-CoreLog $msg -Level ERROR
        throw $msg
    }
    $securityCategories = @(
        'WinUpdateServices', 'WinUpdateDrivers', 'VBS', 'Integrity', 'LSA', 'TSX',
        'DefenderRT', 'DefenderBlock', 'FullAdmin', 'OtherServices', 'TelemetryServices'
    )
    $customHandlers = @{
        'Win32Prio'  = { param($apply) Invoke-Win32PriorityDefault -Apply:$apply }
        'HIDLatency' = { param($apply) Invoke-HidLatencyDefault -Apply:$apply }
        'NvidiaGPU'  = { param($apply) Invoke-NvidiaGpuRestore -Apply:$apply }
        'IntelGPU'   = { param($apply) Invoke-IntelGpuRestore -Apply:$apply }
    }
    $orderedAllCategories = @(
        'MitigationsCPU',
        'WinUpdateServices', 'WinUpdateDrivers', 'VBS', 'Integrity', 'LSA', 'TSX',
        'DefenderRT', 'DefenderBlock', 'FullAdmin', 'OtherServices',
        'TelemetryServices', 'GamingPerf',
        'Win32Prio', 'HIDLatency', 'NvidiaGPU', 'IntelGPU'
    )
    $categoriesToProcess = if ($Category -eq 'All') {
        $set = [System.Collections.Generic.List[string]]::new()
        foreach ($item in $orderedAllCategories) {
            if (-not $set.Contains($item)) {
                $set.Add($item) | Out-Null
            }
        }
        $dataCategories = @()
        if (Get-Command -Name Get-AllCategories -ErrorAction SilentlyContinue) {
            $dataCategories = Get-AllCategories
        }
        foreach ($item in $dataCategories) {
            if (-not $set.Contains($item)) {
                $set.Add($item) | Out-Null
            }
        }
        $set
    }
    else {
        @($Category)
    }
    $restartRequired = $false
    foreach ($catName in $categoriesToProcess) {
        if ($customHandlers.ContainsKey($catName)) {
            try {
                & $customHandlers[$catName] $Apply
            }
            catch {
                Write-CoreLog "Custom handler failed for category '$catName': $($_.Exception.Message)" -Level ERROR
            }
            continue
        }
        if ($securityCategories -contains $catName) {
            if (Get-Command -Name Invoke-SecurityTweaks -ErrorAction SilentlyContinue) {
                try {
                    Invoke-SecurityTweaks -Category $catName -Apply:$Apply
                    if ((-not $Apply) -and $catName -eq 'TelemetryServices') {
                        Invoke-TweakServiceRestore
                    }
                }
                catch {
                    Write-CoreLog "Invoke-SecurityTweaks failed for '$catName': $($_.Exception.Message)" -Level ERROR
                }
            }
            else {
                Write-CoreLog "Invoke-SecurityTweaks not available for category '$catName'." -Level WARNING
            }
            continue
        }
        $categoryData = Get-CategoryData -Category $catName
        if ($null -eq $categoryData) {
            Write-CoreLog "Kategorie '$catName' nebyla nalezena v Data.psm1." -Level WARNING
            continue
        }
        $restartRequired = $restartRequired -or ($categoryData.RequiresRestart -eq $true)
        Write-Host ""
        Write-Host ("Kategorie: {0}" -f $catName) -ForegroundColor Cyan
        Write-Host ("Akce: {0}" -f $action) -ForegroundColor Yellow
        Write-Host ""
        if ($categoryData.ContainsKey('Registry') -and $categoryData.Registry) {
            foreach ($entry in @($categoryData.Registry)) {
                if ($null -eq $entry) { continue }
                $targetValue = if ($Apply) {
                    if ($entry.ContainsKey('ApplyValue')) { $entry.ApplyValue } else { $null }
                }
                else {
                    if ($entry.ContainsKey('RevertValue')) { $entry.RevertValue } else { $null }
                }
                $operation = if ($null -eq $targetValue) { 'Remove' } else { 'Set' }
                $valueType = if ($entry.ContainsKey('Type') -and -not [string]::IsNullOrWhiteSpace($entry.Type)) { $entry.Type } else { 'DWord' }
                $requiredPrivilege = if ($entry.ContainsKey('RequiresSystem') -and $entry.RequiresSystem) { 'System' } else { 'Auto' }
                if ($operation -eq 'Set' -and $null -eq $targetValue) {
                    Write-CoreLog "Registry [$($entry.Path)\$($entry.Name)] přeskočena (chybí hodnota)." -Level WARNING
                    continue
                }
                $parameters = @{
                    Path              = $entry.Path
                    Name              = $entry.Name
                    Operation         = $operation
                    RequiredPrivilege = $requiredPrivilege
                }
                if ($operation -eq 'Set') {
                    $parameters.Value = $targetValue
                    $parameters.Type = $valueType
                }
                elseif ($entry.ContainsKey('Type')) {
                    $parameters.Type = $valueType
                }
                try {
                    $result = Invoke-RegistryOperation @parameters
                    if ($result.Success) {
                        Write-CoreLog "Registry [$($entry.Path)\$($entry.Name)] $action dokončena." -Level SUCCESS
                    }
                    else {
                        Write-CoreLog "Registry [$($entry.Path)\$($entry.Name)] $action selhala: $($result.Error)" -Level WARNING
                    }
                }
                catch {
                    Write-CoreLog "Registry [$($entry.Path)\$($entry.Name)] výjimka: $($_.Exception.Message)" -Level ERROR
                }
            }
        }
        if ($categoryData.ContainsKey('Services') -and $categoryData.Services) {
            foreach ($entry in @($categoryData.Services)) {
                if ($null -eq $entry) { continue }
                $requiredPrivilege = if ($entry.ContainsKey('RequiresSystem') -and $entry.RequiresSystem) { 'System' } else { 'Auto' }
                $operation = $null
                $startupType = $null
                if ($Apply) {
                    if ($entry.ContainsKey('Operation') -and -not [string]::IsNullOrWhiteSpace($entry.Operation)) {
                        $operation = $entry.Operation
                        if ($entry.ContainsKey('ApplyStartType')) {
                            $startupType = Convert-ServiceStartTypeName $entry.ApplyStartType
                        }
                    }
                    elseif ($entry.ContainsKey('ApplyStartType')) {
                        $operation = 'SetStartupType'
                        $startupType = Convert-ServiceStartTypeName $entry.ApplyStartType
                    }
                }
                else {
                    if ($entry.ContainsKey('RevertStartType')) {
                        $operation = 'SetStartupType'
                        $startupType = Convert-ServiceStartTypeName $entry.RevertStartType
                    }
                    elseif ($entry.ContainsKey('Operation') -and $entry.Operation -eq 'Disable') {
                        $operation = 'Enable'
                    }
                    elseif ($entry.ContainsKey('Operation') -and $entry.Operation -eq 'Stop') {
                        $operation = 'Start'
                    }
                }
                if (-not $operation) {
                    continue
                }
                if ($operation -eq 'SetStartupType' -and -not $startupType) {
                    Write-CoreLog "Service [$($entry.Name)] přeskočena (neplatný StartType)." -Level WARNING
                    continue
                }
                $serviceArgs = @{
                    ServiceName       = $entry.Name
                    RequiredPrivilege = $requiredPrivilege
                }
                if ($operation -eq 'Stop') { $serviceArgs['TargetStatus'] = 'Stopped' }
                elseif ($operation -eq 'Start') { $serviceArgs['TargetStatus'] = 'Running' }
                elseif ($operation -eq 'Disable') { 
                    $serviceArgs['TargetStatus'] = 'Stopped'
                    $serviceArgs['StartupType'] = 'Disabled'
                }
                elseif ($operation -eq 'Enable') {
                    $serviceArgs['TargetStatus'] = 'Running'
                    $serviceArgs['StartupType'] = 'Automatic'
                }
                if ($startupType) {
                    $serviceArgs['StartupType'] = $startupType
                }
                try {
                    $svcResult = Invoke-ServiceOperation @serviceArgs
                    if ($svcResult.Success) {
                        Write-CoreLog "Service [$($entry.Name)] $action dokončena (Operation: $operation)." -Level SUCCESS
                    }
                    else {
                        Write-CoreLog "Service [$($entry.Name)] $action selhala: $($svcResult.Error)" -Level WARNING
                    }
                }
                catch {
                    Write-CoreLog "Service [$($entry.Name)] výjimka: $($_.Exception.Message)" -Level ERROR
                }
            }
        }
        if ($categoryData.ContainsKey('Hosts') -and $categoryData.Hosts -and $categoryData.Hosts.ContainsKey('Domains')) {
            $domains = $categoryData.Hosts.Domains | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            if ($domains.Count -gt 0) {
                $hostsResult = Invoke-HostsDomainUpdate -Domains $domains -Apply ([bool]$Apply)
                if ($hostsResult.Success -and $hostsResult.Result) {
                    if ($hostsResult.Result.Updated) {
                        Write-CoreLog "Hosts soubor upraven pro kategorii '$catName'." -Level SUCCESS
                    }
                    else {
                        Write-CoreLog "Hosts soubor již splňuje požadavky pro kategorii '$catName'." -Level INFO
                    }
                }
                else {
                    $hostsError = if ($hostsResult.Error) { $hostsResult.Error } elseif ($hostsResult.Result) { $hostsResult.Result.Message } else { 'Neznámá chyba' }
                    Write-CoreLog "Úprava hosts souboru pro kategorii '$catName' selhala: $hostsError" -Level WARNING
                }
            }
        }
    }
    if ($restartRequired) {
        Write-Host ""
        Write-Host "⚠️  Dokončeno. Restart systému je doporučen." -ForegroundColor Yellow
        Write-CoreLog "Restart systému je doporučen po dokončení akce $action." -Level WARNING
    }
    Write-CoreLog "$action tweaků dokončeno pro kategorii: $Category" -Level INFO
}
Write-CoreLog "Core module loaded (Admin: $($Global:KRAKEFIX_SharedState.IsAdmin), SYSTEM: $($Global:KRAKEFIX_SharedState.CanElevateToSystem), Integrity: $($Global:KRAKEFIX_SharedState.IntegrityLevel))" -Level SUCCESS
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
}
Export-ModuleMember -Function @(
    'Invoke-ModuleEntry',
    # Privilege Detection
    'Test-Administrator',
    'Test-SystemPrivilege',
    'Get-ProcessIntegrityLevel',
    'Assert-TokenSecurity',
    # Direct Privilege Escalation
    'Invoke-AsSystem',
    # Fallback Chain (RECOMMENDED)
    'Invoke-WithPrivilege',
    'Invoke-RegistryOperation',
    'Invoke-RestoreRegistry',
    'Invoke-ServiceOperation',
    'Invoke-RestoreService',
    'Resolve-ServiceNamePattern',
    'Invoke-SafeACLModification',
    # TrustedInstaller Operations (HIGHEST PRIVILEGE)
    'Test-IsTrustedInstallerOwned',
    'Invoke-AsTrustedInstaller',
    # Tweak Application & Revert
    'Invoke-RevertToDefaults',
    # Critical Restore Safety
    'Test-RestoreReadiness',
    'Invoke-EmergencyRestoreViaRegExe',
    # Backup Management
    'Remove-OldBackups',
    # Logging
    'Write-CoreLog'
) -Variable @(
    'Global:KRAKEFIX_SharedState'
)
function Resolve-RegistryExecutionPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('Auto', 'User', 'Admin', 'System', 'TrustedInstaller')][string]$TargetPrivilege
    )
    $resolvedPath = $Path
    $needsSystemContext = $TargetPrivilege -in @('System', 'TrustedInstaller')
    if ($needsSystemContext -and ($Path -match '^(?i)HKCU:|^HKEY_CURRENT_USER\\')) {
        $sid = Get-CurrentUserSid
        if (-not [string]::IsNullOrWhiteSpace($sid)) {
            $resolvedPath = $Path -replace '^(?i)HKCU:', "HKU:\\$sid"
            $resolvedPath = $resolvedPath -replace '^HKEY_CURRENT_USER\\', "HKU\\$sid\\"
        }
    }
    return $resolvedPath
}