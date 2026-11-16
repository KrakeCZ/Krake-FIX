#Requires -Version 5.1
#Requires -RunAsAdministrator

# KRAKE-FIX ACL management module. All destructive actions require explicit confirmation.

function Invoke-ModuleEntry {
    [CmdletBinding()]
    param([hashtable]$ModuleContext)
    Show-AclMainMenu
}

function Read-AclTargetPath {
    param([string]$Prompt = 'Zadejte úplnou cestu ke složce nebo souboru')
    $path = (Read-Host $Prompt).Trim().Trim('"')
    if ([string]::IsNullOrWhiteSpace($path) -or -not (Test-Path -LiteralPath $path)) {
        Write-Host 'Cesta nebyla zadána nebo neexistuje.' -ForegroundColor Red
        return $null
    }
    return (Get-Item -LiteralPath $path -ErrorAction Stop).FullName
}

function Confirm-AclChange {
    param([Parameter(Mandatory)][string]$Action, [Parameter(Mandatory)][string]$Path)
    Write-Host "\nPozor: $Action" -ForegroundColor Yellow
    Write-Host "Cíl: $Path" -ForegroundColor Yellow
    $answer = Read-Host 'Pokračovat? Napište PRESNE ANO'
    return ($answer -ceq 'ANO')
}

function Select-AclPrincipal {
    Write-Host '1. SYSTEM (*S-1-5-18)'
    Write-Host '2. Administrators / Správci (*S-1-5-32-544)'
    Write-Host '3. Users / Uživatelé (*S-1-5-32-545)'
    Write-Host '4. Everyone / Všichni (*S-1-1-0)'
    Write-Host "5. Aktuální účet ($env:USERDOMAIN\$env:USERNAME)"
    Write-Host '6. Vlastní účet nebo SID'
    switch (Read-Host 'Účet') {
        '1' { return '*S-1-5-18' }
        '2' { return '*S-1-5-32-544' }
        '3' { return '*S-1-5-32-545' }
        '4' { return '*S-1-1-0' }
        '5' { return "$env:USERDOMAIN\$env:USERNAME" }
        '6' {
            $principal = (Read-Host 'Zadejte název účtu nebo SID').Trim()
            if ($principal -match '[\r\n"]' -or [string]::IsNullOrWhiteSpace($principal)) { return $null }
            if ($principal -match '^S-1-' -and $principal -notmatch '^\*S-1-') { return "*$principal" }
            return $principal
        }
        default { return $null }
    }
}

function Select-AclPermission {
    Write-Host '1. F  - Úplné řízení'
    Write-Host '2. M  - Úpravy'
    Write-Host '3. RX - Čtení a spouštění'
    Write-Host '4. R  - Pouze čtení'
    Write-Host '5. W  - Zápis'
    switch (Read-Host 'Oprávnění') {
        '1' { return 'F' }
        '2' { return 'M' }
        '3' { return 'RX' }
        '4' { return 'R' }
        '5' { return 'W' }
        default { return $null }
    }
}

function Invoke-IcaclsChecked {
    param([Parameter(Mandatory)][string[]]$Arguments)
    & "$env:SystemRoot\System32\icacls.exe" @Arguments
    if ($LASTEXITCODE -ne 0) {
        Write-Host "icacls skončil s kódem $LASTEXITCODE. Zkontrolujte výstup výše." -ForegroundColor Red
        return $false
    }
    return $true
}

function Show-AdvancedAclMenu {
    while ($true) {
        Clear-Host
        Write-Host '============= POKROČILÁ SPRÁVA ACL =============' -ForegroundColor Magenta
        Write-Host '1. Zobrazit oprávnění'
        Write-Host '2. Zálohovat ACL (/save, rekurzivně)'
        Write-Host '3. Obnovit ACL ze zálohy (/restore)'
        Write-Host '4. Nastavit vlastníka'
        Write-Host '5. Udělit oprávnění'
        Write-Host '6. Odebrat explicitní oprávnění'
        Write-Host '7. Odepřít oprávnění (DENY)'
        Write-Host '8. Nastavit dědičnost'
        Write-Host '9. Hledat podle SID (/findsid)'
        Write-Host '0. Zpět'
        $choice = Read-Host 'Volba'
        if ($choice -eq '0') { return }
        $path = Read-AclTargetPath
        if (-not $path) { [void](Read-Host 'Enter pro pokračování'); continue }

        switch ($choice) {
            '1' { Invoke-IcaclsChecked -Arguments @($path); [void](Read-Host 'Enter') }
            '2' {
                $backup = (Read-Host 'Úplná cesta záložního souboru').Trim().Trim('"')
                if ([string]::IsNullOrWhiteSpace($backup)) { continue }
                if (Test-Path -LiteralPath $backup) { Write-Host 'Soubor již existuje; záloha by jej přepsala.' -ForegroundColor Red; [void](Read-Host 'Enter'); continue }
                if (Confirm-AclChange 'Rekurzivní export ACL' $path) {
                    $parent = Split-Path -Parent $path
                    $leaf = Split-Path -Leaf $path
                    if (-not $parent) { $parent = $path; $leaf = '.' }
                    $null = Invoke-IcaclsChecked -Arguments @((Join-Path $parent $leaf), '/save', $backup, '/T', '/C', '/Q')
                }
                [void](Read-Host 'Enter')
            }
            '3' {
                $backup = (Read-Host 'Cesta k záložnímu souboru').Trim().Trim('"')
                if (-not (Test-Path -LiteralPath $backup -PathType Leaf)) { Write-Host 'Záloha neexistuje.' -ForegroundColor Red; [void](Read-Host 'Enter'); continue }
                if (Confirm-AclChange 'Obnovení ACL ze zálohy (může změnit mnoho položek)' $path) {
                    $restoreRoot = if ((Get-Item -LiteralPath $path).PSIsContainer) { $path } else { Split-Path -Parent $path }
                    $null = Invoke-IcaclsChecked -Arguments @($restoreRoot, '/restore', $backup, '/C', '/Q')
                }
                [void](Read-Host 'Enter')
            }
            '4' {
                $principal = Select-AclPrincipal
                if ($principal -and (Confirm-AclChange "Změna vlastníka na $principal" $path)) {
                    $recursive = (Read-Host 'Rekurzivně? (A/N)') -match '^[Aa]$'
                    $args = @($path, '/setowner', $principal, '/C')
                    if ($recursive) { $args += '/T' }
                    $null = Invoke-IcaclsChecked -Arguments $args
                }
                [void](Read-Host 'Enter')
            }
            '5' {
                $principal = Select-AclPrincipal; $perm = Select-AclPermission
                if ($principal -and $perm -and (Confirm-AclChange "Udělení $perm účtu $principal" $path)) {
                    $recursive = (Read-Host 'Rekurzivně včetně dědění na soubory a složky? (A/N)') -match '^[Aa]$'
                    $grant = if ($recursive) { "${principal}:(OI)(CI)$perm" } else { "${principal}:$perm" }
                    $args = @($path, '/grant', $grant, '/C')
                    if ($recursive) { $args += '/T' }
                    $null = Invoke-IcaclsChecked -Arguments $args
                }
                [void](Read-Host 'Enter')
            }
            '6' {
                $principal = Select-AclPrincipal
                if ($principal -and (Confirm-AclChange "Odebrání explicitních oprávnění účtu $principal" $path)) {
                    $recursive = (Read-Host 'Rekurzivně? (A/N)') -match '^[Aa]$'
                    $args = @($path, '/remove', $principal, '/C')
                    if ($recursive) { $args += '/T' }
                    $null = Invoke-IcaclsChecked -Arguments $args
                }
                [void](Read-Host 'Enter')
            }
            '7' {
                Write-Host 'DENY může zablokovat přístup i přes jiná povolení. Používejte obezřetně.' -ForegroundColor Red
                $principal = Select-AclPrincipal; $perm = Select-AclPermission
                if ($principal -and $perm -and (Confirm-AclChange "Odepření $perm účtu $principal" $path)) {
                    $recursive = (Read-Host 'Rekurzivně? (A/N)') -match '^[Aa]$'
                    $deny = if ($recursive) { "${principal}:(OI)(CI)$perm" } else { "${principal}:$perm" }
                    $args = @($path, '/deny', $deny, '/C')
                    if ($recursive) { $args += '/T' }
                    $null = Invoke-IcaclsChecked -Arguments $args
                }
                [void](Read-Host 'Enter')
            }
            '8' {
                Write-Host '1. Povolit dědičnost (e)'; Write-Host '2. Zakázat a zkopírovat zděděná práva (d)'; Write-Host '3. Zakázat a odstranit zděděná práva (r)'
                $flag = switch (Read-Host 'Volba') { '1' { 'e' } '2' { 'd' } '3' { 'r' } default { $null } }
                if ($flag -and (Confirm-AclChange "Změna dědičnosti /inheritance:$flag" $path)) {
                    $null = Invoke-IcaclsChecked -Arguments @($path, "/inheritance:$flag", '/C')
                }
                [void](Read-Host 'Enter')
            }
            '9' {
                $principal = Select-AclPrincipal
                if ($principal) { $null = Invoke-IcaclsChecked -Arguments @($path, '/findsid', $principal, '/T', '/C') }
                [void](Read-Host 'Enter')
            }
            default { Write-Host 'Neplatná volba.' -ForegroundColor Red; Start-Sleep 1 }
        }
    }
}

function Show-AclMainMenu {
    while ($true) {
        Clear-Host
        Write-Host '============= ACL / ICACLS =============' -ForegroundColor Cyan
        Write-Host '1. Zálohovat ACL vybrané cesty'
        Write-Host '2. Obnovit ACL ze zálohy'
        Write-Host '3. Resetovat ACL na zděděné výchozí hodnoty pro vlastní cestu'
        Write-Host '4. Pokročilá správa ACL'
        Write-Host '0. Zpět do KRAKE-FIX'
        $choice = Read-Host 'Volba'
        switch ($choice) {
            '0' { return }
            '1' {
                $path = Read-AclTargetPath
                if ($path) {
                    $backup = (Read-Host 'Cesta k nové záloze').Trim().Trim('"')
                    if ($backup -and -not (Test-Path -LiteralPath $backup) -and (Confirm-AclChange 'Rekurzivní záloha ACL' $path)) {
                        $parent = Split-Path -Parent $path; $leaf = Split-Path -Leaf $path
                        if (-not $parent) { $parent = $path; $leaf = '.' }
                        $null = Invoke-IcaclsChecked -Arguments @((Join-Path $parent $leaf), '/save', $backup, '/T', '/C', '/Q')
                    } elseif (Test-Path -LiteralPath $backup) { Write-Host 'Záložní soubor již existuje; nebyl přepsán.' -ForegroundColor Yellow }
                }
                [void](Read-Host 'Enter')
            }
            '2' {
                $path = Read-AclTargetPath
                $backup = (Read-Host 'Cesta k záložnímu souboru').Trim().Trim('"')
                if ($path -and (Test-Path -LiteralPath $backup -PathType Leaf) -and (Confirm-AclChange 'Obnovení ACL ze zálohy' $path)) {
                    $root = if ((Get-Item -LiteralPath $path).PSIsContainer) { $path } else { Split-Path -Parent $path }
                    $null = Invoke-IcaclsChecked -Arguments @($root, '/restore', $backup, '/C', '/Q')
                } else { Write-Host 'Neplatná cesta nebo záloha.' -ForegroundColor Red }
                [void](Read-Host 'Enter')
            }
            '3' {
                $path = Read-AclTargetPath
                if ($path -and (Confirm-AclChange 'Rekurzivní reset ACL (/reset /T). Může odstranit vlastní ACL nastavení.' $path)) {
                    $null = Invoke-IcaclsChecked -Arguments @($path, '/reset', '/T', '/C', '/Q')
                }
                [void](Read-Host 'Enter')
            }
            '4' { Show-AdvancedAclMenu }
            default { Write-Host 'Neplatná volba.' -ForegroundColor Red; Start-Sleep 1 }
        }
    }
}

Export-ModuleMember -Function Invoke-ModuleEntry, Show-AclMainMenu, Show-AdvancedAclMenu
