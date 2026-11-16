# ═══════════════════════════════════════════════════════════════════════════════
# Module: ACL.psm1
# Purpose: ACL / icacls management and restore tools
# Requires: Administrator
# ═══════════════════════════════════════════════════════════════════════════════

#Requires -Version 5.1
#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}
catch {
    # Ignorovat v prostředích bez standardní konzole
}

function Invoke-ModuleEntry {
    [CmdletBinding()]
    param(
        [hashtable]$ModuleContext
    )

    Show-AclMainMenu
}

function Invoke-AclPause {
    Write-Host ""
    Write-Host "Stiskněte Enter pro pokračování..." -ForegroundColor Gray -NoNewline
    $null = Read-Host
}

function Repair-ProgramFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $ErrorActionPreference = 'Continue'
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Host "[CHYBA] Cesta $Path neexistuje." -ForegroundColor Red
        return
    }

    Write-Host "`n[INFO] Opravuji oprávnění pro: $Path ..." -ForegroundColor Green
    icacls "$Path" /reset /T /C /L /Q
    icacls "$Path" /grant "*S-1-5-32-545:(OI)(CI)RX" /T /C /L /Q
    Write-Host "[OK] Hotovo: $Path" -ForegroundColor Green
}

function Repair-ProgramData {
    [CmdletBinding()]
    param()

    $ErrorActionPreference = 'Continue'
    $Path = "C:\ProgramData"
    Write-Host "`n[INFO] Opravuji specifická oprávnění pro: $Path ..." -ForegroundColor Green

    icacls "$Path" /setowner "*S-1-5-32-544" /C /L /Q
    icacls "$Path" /grant "*S-1-5-18:(OI)(CI)F" /C /L /Q
    icacls "$Path" /grant "*S-1-5-32-544:(OI)(CI)F" /C /L /Q
    icacls "$Path" /grant "*S-1-5-32-545:(OI)(CI)RX" /C /L /Q
    icacls "$Path" /grant "*S-1-3-0:(OI)(CI)(IO)F" /C /L /Q
    icacls "$Path\*" /reset /T /C /L /Q

    Write-Host "[OK] Hotovo: $Path" -ForegroundColor Green
}

function Repair-UserFolder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$UserPath
    )

    $ErrorActionPreference = 'Continue'
    if (-not (Test-Path -LiteralPath $UserPath)) {
        Write-Host "[CHYBA] Složka $UserPath neexistuje." -ForegroundColor Red
        return
    }

    Write-Host "`n[INFO] Opravuji uživatelskou složku: $UserPath ..." -ForegroundColor Green
    icacls "$UserPath" /reset /T /C /L /Q
    Write-Host "[OK] Hotovo: $UserPath" -ForegroundColor Green
}

function Select-TargetUser {
    [CmdletBinding()]
    param()

    Write-Host "`nVyberte uživatele nebo skupinu:" -ForegroundColor Yellow
    Write-Host "1. SYSTEM (*S-1-5-18)"
    Write-Host "2. Administrators / Správci (*S-1-5-32-544)"
    Write-Host "3. Users / Uživatelé (*S-1-5-32-545)"
    Write-Host "4. Everyone / Všichni (*S-1-1-0)"
    Write-Host "5. Aktuálně přihlášený uživatel ($env:USERNAME)"
    Write-Host "6. Zadat vlastní název účtu nebo skupiny"

    $uChoice = Read-Host "Volba účtu"
    switch ($uChoice) {
        '1' { return "*S-1-5-18" }
        '2' { return "*S-1-5-32-544" }
        '3' { return "*S-1-5-32-545" }
        '4' { return "*S-1-1-0" }
        '5' { return "$env:USERNAME" }
        '6' { return (Read-Host "Zadejte název uživatele/skupiny") }
        default { return $null }
    }
}

function Select-PermissionLevel {
    [CmdletBinding()]
    param()

    Write-Host "`nVyberte úroveň oprávnění:" -ForegroundColor Yellow
    Write-Host "1. F  - Úplné řízení (Full control)"
    Write-Host "2. M  - Úpravy (Modify - čtení, zápis, mazání)"
    Write-Host "3. RX - Čtení a spouštění (Read & Execute)"
    Write-Host "4. R  - Pouze čtení (Read-only)"
    Write-Host "5. W  - Pouze zápis (Write-only)"

    $pChoice = Read-Host "Volba oprávnění"
    switch ($pChoice) {
        '1' { return "F" }
        '2' { return "M" }
        '3' { return "RX" }
        '4' { return "R" }
        '5' { return "W" }
        default { return $null }
    }
}

function Show-AclMainMenu {
    [CmdletBinding()]
    param()

    $ErrorActionPreference = 'Continue'

    do {
        Clear-Host
        Write-Host "=====================================================" -ForegroundColor Cyan
        Write-Host "      INTERAKTIVNÍ SPRÁVA A OBNOVA ACL (WIN 11)      " -ForegroundColor Cyan
        Write-Host "=====================================================" -ForegroundColor Cyan
        Write-Host "1. Opravit C:\Program Files"
        Write-Host "2. Opravit C:\Program Files (x86)"
        Write-Host "3. Opravit C:\ProgramData"
        Write-Host "4. Opravit Uživatelský profil (C:\Users\<jméno>)"
        Write-Host "5. VŠECHNY VÝŠE UVEDENÉ SLOŽKY (kompletní obnova)" -ForegroundColor Yellow
        Write-Host "6. Rychlý reset vlastní složky (icacls /reset)" -ForegroundColor Cyan
        Write-Host "7. POKROČILÝ NÁSTROJ ICACLS (komplexní správa práv)" -ForegroundColor Magenta
        Write-Host "0. Zpět do hlavního menu"
        Write-Host "=====================================================" -ForegroundColor Cyan

        $choice = Read-Host "Zadejte číslo volby"

        switch ($choice) {
            '1' {
                Repair-ProgramFiles "C:\Program Files"
                Invoke-AclPause
            }
            '2' {
                Repair-ProgramFiles "C:\Program Files (x86)"
                Invoke-AclPause
            }
            '3' {
                Repair-ProgramData
                Invoke-AclPause
            }
            '4' {
                Write-Host "`nDostupné profily v C:\Users:" -ForegroundColor Yellow
                Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -notin @("Public", "Default", "Default User", "All Users") } |
                    ForEach-Object { Write-Host " - $($_.Name)" }

                $userName = Read-Host "`nZadejte přesný název složky uživatele"
                if (-not [string]::IsNullOrWhiteSpace($userName)) {
                    Repair-UserFolder "C:\Users\$userName"
                }
                Invoke-AclPause
            }
            '5' {
                $confirm = Read-Host "Opravdu chcete resetovat práva pro Program Files, (x86), ProgramData i aktuálního uživatele? (A/N)"
                if ($confirm -eq 'A' -or $confirm -eq 'a') {
                    Repair-ProgramFiles "C:\Program Files"
                    Repair-ProgramFiles "C:\Program Files (x86)"
                    Repair-ProgramData
                    Repair-UserFolder $env:USERPROFILE
                    Write-Host "`n[HOTOVO] Všechny vybrané složky byly opraveny." -ForegroundColor Cyan
                }
                Invoke-AclPause
            }
            '6' {
                $customPath = (Read-Host "Zadejte celou cestu ke složce (např. D:\Hry)").Trim('"')
                if (-not [string]::IsNullOrWhiteSpace($customPath) -and (Test-Path -LiteralPath $customPath)) {
                    icacls "$customPath" /reset /T /C /L /Q
                    Write-Host "[OK] Práva pro $customPath byla resetována." -ForegroundColor Green
                }
                else {
                    Write-Host "[CHYBA] Cesta neexistuje." -ForegroundColor Red
                }
                Invoke-AclPause
            }
            '7' {
                Show-AdvancedIcaclsMenu
            }
            '0' {
                Write-Host "Vracím se do hlavního menu..." -ForegroundColor Gray
                return
            }
            default {
                Write-Host "Neplatná volba." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($choice -ne '0')
}

function Show-AdvancedIcaclsMenu {
    [CmdletBinding()]
    param()

    $ErrorActionPreference = 'Continue'

    do {
        Clear-Host
        Write-Host "=====================================================" -ForegroundColor Magenta
        Write-Host "         POKROČILÝ NÁSTROJ ICACLS (PODMENU)          " -ForegroundColor Magenta
        Write-Host "=====================================================" -ForegroundColor Magenta
        Write-Host "1. Zobrazit aktuální ACL oprávnění složky/souboru"
        Write-Host "2. ZÁLOHOVAT ACL oprávnění do souboru (/save)" -ForegroundColor Green
        Write-Host "3. OBNOVIT ACL oprávnění ze zálohy (/restore)" -ForegroundColor Green
        Write-Host "4. Převzít vlastnictví složky/souboru (/setowner)"
        Write-Host "5. UDĚLIT oprávnění uživateli/skupině (/grant)"
        Write-Host "6. ODEBRAT oprávnění uživateli/skupině (/remove)"
        Write-Host "7. ZAKÁZAT (odepřít) oprávnění (/deny)" -ForegroundColor Red
        Write-Host "8. Správa dědičnosti (/inheritance: e / d / r)"
        Write-Host "9. Hledat soubory podle vlastníka (/findsid)"
        Write-Host "0. Zpět do ACL menu"
        Write-Host "=====================================================" -ForegroundColor Magenta

        $subChoice = Read-Host "Zadejte číslo volby"
        if ($subChoice -eq '0') { return }

        $targetPath = (Read-Host "`nZadejte cílovou cestu ke složce nebo souboru").Trim('"')
        if ([string]::IsNullOrWhiteSpace($targetPath) -or -not (Test-Path -LiteralPath $targetPath)) {
            Write-Host "[CHYBA] Zadaná cesta neexistuje!" -ForegroundColor Red
            Invoke-AclPause
            continue
        }

        switch ($subChoice) {
            '1' {
                Write-Host "`n--- Aktuální oprávnění pro: $targetPath ---" -ForegroundColor Cyan
                icacls "$targetPath"
                Invoke-AclPause
            }
            '2' {
                $backupFile = (Read-Host "Zadejte cestu a název záložního souboru (např. C:\acl_zaloha.txt)").Trim('"')
                if (-not [string]::IsNullOrWhiteSpace($backupFile)) {
                    Write-Host "[INFO] Vytvářím rekurzivní zálohu ACL..." -ForegroundColor Green
                    icacls "$targetPath" /save "$backupFile" /T /C /L /Q
                    Write-Host "[OK] Záloha uložena do: $backupFile" -ForegroundColor Green
                }
                Invoke-AclPause
            }
            '3' {
                $backupFile = (Read-Host "Zadejte cestu k záložnímu souboru (např. C:\acl_zaloha.txt)").Trim('"')
                if (-not [string]::IsNullOrWhiteSpace($backupFile) -and (Test-Path -LiteralPath $backupFile)) {
                    $parentDir = Split-Path -Path $targetPath -Parent
                    if ([string]::IsNullOrEmpty($parentDir)) { $parentDir = $targetPath }

                    Write-Host "[INFO] Obnovuji oprávnění ze zálohy do nadřazené cesty: $parentDir ..." -ForegroundColor Yellow
                    icacls "$parentDir" /restore "$backupFile" /C /L /Q
                    Write-Host "[OK] Obnova ze zálohy dokončena." -ForegroundColor Green
                }
                else {
                    Write-Host "[CHYBA] Záložní soubor neexistuje!" -ForegroundColor Red
                }
                Invoke-AclPause
            }
            '4' {
                $owner = Select-TargetUser
                if ($owner) {
                    $rec = Read-Host "Aplikovat rekurzivně na všechny podsložky a soubory? (A/N)"
                    if ($rec -eq 'A' -or $rec -eq 'a') {
                        icacls "$targetPath" /setowner "$owner" /T /C /L /Q
                    }
                    else {
                        icacls "$targetPath" /setowner "$owner" /C /L /Q
                    }
                    Write-Host "[OK] Vlastník změněn na: $owner" -ForegroundColor Green
                }
                Invoke-AclPause
            }
            '5' {
                $user = Select-TargetUser
                $perm = Select-PermissionLevel
                if ($user -and $perm) {
                    $rec = Read-Host "Aplikovat rekurzivně včetně dědičnosti (OI)(CI) na podsložky? (A/N)"
                    if ($rec -eq 'A' -or $rec -eq 'a') {
                        icacls "$targetPath" /grant "${user}:(OI)(CI)${perm}" /T /C /L /Q
                    }
                    else {
                        icacls "$targetPath" /grant "${user}:${perm}" /C /L /Q
                    }
                    Write-Host "[OK] Uděleno oprávnění $perm pro $user." -ForegroundColor Green
                }
                Invoke-AclPause
            }
            '6' {
                $user = Select-TargetUser
                if ($user) {
                    $rec = Read-Host "Odebrat oprávnění rekurzivně ze všech podsložek? (A/N)"
                    if ($rec -eq 'A' -or $rec -eq 'a') {
                        icacls "$targetPath" /remove "$user" /T /C /L /Q
                    }
                    else {
                        icacls "$targetPath" /remove "$user" /C /L /Q
                    }
                    Write-Host "[OK] Veškerá explicitní práva pro $user byla odebrána." -ForegroundColor Green
                }
                Invoke-AclPause
            }
            '7' {
                Write-Host "[VAROVÁNÍ] Zakázání práv (/deny) má vždy přednost před povolením!" -ForegroundColor Red
                $user = Select-TargetUser
                $perm = Select-PermissionLevel
                if ($user -and $perm) {
                    $rec = Read-Host "Aplikovat zákaz rekurzivně (OI)(CI)? (A/N)"
                    if ($rec -eq 'A' -or $rec -eq 'a') {
                        icacls "$targetPath" /deny "${user}:(OI)(CI)${perm}" /T /C /L /Q
                    }
                    else {
                        icacls "$targetPath" /deny "${user}:${perm}" /C /L /Q
                    }
                    Write-Host "[OK] Nastaven zákaz ($perm) pro $user." -ForegroundColor Yellow
                }
                Invoke-AclPause
            }
            '8' {
                Write-Host "`nVyberte režim dědičnosti:" -ForegroundColor Yellow
                Write-Host "1. e - Povolit dědičnost z nadřazené složky"
                Write-Host "2. d - Zakázat dědičnost a zkopírovat zděděná práva jako explicitní"
                Write-Host "3. r - Zakázat dědičnost a SMAZAT všechna zděděná práva"

                $inhChoice = Read-Host "Volba dědičnosti"
                $inhFlag = switch ($inhChoice) {
                    '1' { "e" }
                    '2' { "d" }
                    '3' { "r" }
                    default { $null }
                }

                if ($inhFlag) {
                    icacls "$targetPath" /inheritance:$inhFlag /C /L
                    Write-Host "[OK] Režim dědičnosti nastaven na: /inheritance:$inhFlag" -ForegroundColor Green
                }
                Invoke-AclPause
            }
            '9' {
                $user = Select-TargetUser
                if ($user) {
                    Write-Host "`n[INFO] Hledám položky vlastněné účtem $user v $targetPath ..." -ForegroundColor Cyan
                    icacls "$targetPath" /findsid "$user" /T /C /L
                }
                Invoke-AclPause
            }
            default {
                Write-Host "Neplatná volba." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    } while ($true)
}

Export-ModuleMember -Function Invoke-ModuleEntry, Show-AclMainMenu, Show-AdvancedIcaclsMenu
