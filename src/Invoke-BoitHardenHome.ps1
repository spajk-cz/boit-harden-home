#Requires -Version 5.1
<#
.SYNOPSIS
    BOIT Harden Home - interaktivni hardening & privacy audit nastroj pro domaci Windows.

.DESCRIPTION
    Projde nastaveni Windows podle rozumne podmnoziny Microsoft Security Baseline
    a CIS Benchmarku (profil pro domaci/standalone stanici) plus privacy vrstvy.

    Tri rezimy:
      - Audit  : jen cte, nic nemeni, vyplivne HTML report (co je OK / co je fuck up).
      - Harden : aplikuje zmeny podle zvolene urovne rizika. PRED kazdou zmenou
                 zazalohuje presny puvodni stav do transakcniho logu (JSON).
      - Revert : vrati zmeny z vybraneho (nebo posledniho) behu zpatky do puvodu.

    Revert je prvotridni funkce. Kazda zmena, kterou nastroj provede, je zapsana
    tak, aby sla presne vratit:
      - hodnota predtim existovala  -> nastavi se zpet puvodni hodnota a typ,
      - hodnota predtim neexistovala -> hodnota se smaze (pripadne i vytvoreny klic).

    Vse jen pres registr -> rollback je genericky a spolehlivy. Dalsi typy
    (ASR pravidla, Defender, sluzby s vlastni logikou) prijdou v dalsi iteraci
    s vlastni capture/revert logikou.

.NOTES
    Delame #BezpecnejsiCesko
    Spoustet jako administrator. Nejdriv otestovat na virtualce.
#>

[CmdletBinding()]
param(
    [ValidateSet('Menu', 'Audit', 'Harden', 'Revert')]
    [string]$Mode = 'Menu',

    # Uroven rizika pro Harden. Vyssi uroven zahrnuje nizsi.
    [ValidateSet('Safe', 'Moderate', 'Aggressive')]
    [string]$Tier = 'Safe',

    # Konkretni run log pro Revert. Kdyz neni, pouzije se posledni.
    [string]$RunFile,

    # Preskoci interaktivni potvrzeni (pro automatizaci / testy na VM).
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'
$script:AppName   = 'BOIT Harden Home'
$script:Lime      = 'D3FC23'
$script:DataDir   = Join-Path $env:ProgramData 'BOIT-Harden'
$script:RunsDir   = Join-Path $script:DataDir 'runs'
$script:ReportDir = Join-Path $script:DataDir 'reports'

$script:RiskRank = @{ Safe = 1; Moderate = 2; Aggressive = 3 }

#region ---------------------------------------------------------- Pravidla
# Kazde pravidlo = jedna registrova hodnota.
#   Id    - stabilni identifikator
#   Cat   - kategorie (Zabezpeceni / Soukromi)
#   Title - kratky nazev (CZ)
#   Desc  - co to dela (CZ)
#   Why   - proc to resit (CZ)
#   Risk  - Safe / Moderate / Aggressive
#   Hive  - HKLM / HKCU
#   Key   - podklic bez hive
#   Name  - nazev hodnoty
#   Type  - DWord / String / QWord / MultiString / ExpandString
#   Value - pozadovana hodnota
function Get-HardeningRules {
    @(
        # ----------------------------- ZABEZPECENI -----------------------------
        @{ Id = 'SEC-UAC-ENABLE'; Cat = 'Zabezpeceni'; Title = 'UAC zapnuto'
           Desc = 'Zajisti, ze je Rizeni uzivatelskych uctu (UAC) zapnute.'
           Why  = 'Bez UAC bezi aplikace rovnou s plnymi pravy, coz je raj pro malware.'
           Risk = 'Safe'; Hive = 'HKLM'; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableLUA'; Type = 'DWord'; Value = 1 }

        @{ Id = 'SEC-UAC-SECUREDESKTOP'; Cat = 'Zabezpeceni'; Title = 'UAC dotaz na zabezpecene plose'
           Desc = 'UAC dotaz se zobrazi na zatmavene zabezpecene plose.'
           Why  = 'Znemoznuje aplikaci predstirat nebo odklikat UAC dotaz za uzivatele.'
           Risk = 'Safe'; Hive = 'HKLM'; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'PromptOnSecureDesktop'; Type = 'DWord'; Value = 1 }

        @{ Id = 'SEC-UAC-ADMINPROMPT'; Cat = 'Zabezpeceni'; Title = 'UAC vzdy vyzadovat souhlas'
           Desc = 'Administrator je u akci s vyssimi pravy vzdy dotazan na souhlas.'
           Why  = 'Ztezuje tichou eskalaci opravneni. Cena je o neco vic dotazu.'
           Risk = 'Moderate'; Hive = 'HKLM'; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ConsentPromptBehaviorAdmin'; Type = 'DWord'; Value = 2 }

        @{ Id = 'SEC-SMARTSCREEN-ON'; Cat = 'Zabezpeceni'; Title = 'SmartScreen zapnuty'
           Desc = 'Zapne kontrolu stahovanych souboru a spoustenych aplikaci pres SmartScreen.'
           Why  = 'Blokuje znamy skodlivy a nedoveryhodny obsah jeste pred spustenim.'
           Risk = 'Safe'; Hive = 'HKLM'; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'EnableSmartScreen'; Type = 'DWord'; Value = 1 }

        @{ Id = 'SEC-SMARTSCREEN-BLOCK'; Cat = 'Zabezpeceni'; Title = 'SmartScreen uroven Block'
           Desc = 'Nastavi SmartScreen tak, aby nedoveryhodny obsah rovnou blokoval.'
           Why  = 'Rezim pouheho varovani se da odklikat; Block je tvrdsi.'
           Risk = 'Moderate'; Hive = 'HKLM'; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Name = 'ShellSmartScreenLevel'; Type = 'String'; Value = 'Block' }

        @{ Id = 'SEC-AUTORUN-OFF'; Cat = 'Zabezpeceni'; Title = 'Automaticke spousteni medii vypnuto'
           Desc = 'Vypne AutoRun/AutoPlay pro vsechny typy jednotek.'
           Why  = 'Klasicky vektor sireni pres USB. Zadne auto-spusteni z media.'
           Risk = 'Safe'; Hive = 'HKLM'; Key = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Name = 'NoDriveTypeAutoRun'; Type = 'DWord'; Value = 255 }

        @{ Id = 'SEC-INSTALLER-ELEV'; Cat = 'Zabezpeceni'; Title = 'AlwaysInstallElevated vypnuto'
           Desc = 'Zakaze instalaci MSI balicku automaticky s pravy systemu.'
           Why  = 'Zapnute AlwaysInstallElevated je ucebnicova cesta k eskalaci opravneni.'
           Risk = 'Safe'; Hive = 'HKLM'; Key = 'SOFTWARE\Policies\Microsoft\Windows\Installer'; Name = 'AlwaysInstallElevated'; Type = 'DWord'; Value = 0 }

        @{ Id = 'SEC-SMB1-SERVER'; Cat = 'Zabezpeceni'; Title = 'SMBv1 server vypnuty'
           Desc = 'Vypne zastaraly protokol SMBv1 na strane serveru.'
           Why  = 'SMBv1 je mrtvy a dirav (EternalBlue a spol.). Nema co delat na sdileni.'
           Risk = 'Safe'; Hive = 'HKLM'; Key = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Name = 'SMB1'; Type = 'DWord'; Value = 0 }

        @{ Id = 'SEC-LLMNR-OFF'; Cat = 'Zabezpeceni'; Title = 'LLMNR vypnuto'
           Desc = 'Vypne multicastove rozlisovani jmen LLMNR.'
           Why  = 'LLMNR je oblibeny MITM vektor (Responder) pro kradez hashu.'
           Risk = 'Moderate'; Hive = 'HKLM'; Key = 'SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name = 'EnableMulticast'; Type = 'DWord'; Value = 0 }

        @{ Id = 'SEC-LSA-PPL'; Cat = 'Zabezpeceni'; Title = 'Ochrana LSASS (RunAsPPL)'
           Desc = 'Spusti proces LSASS jako chraneny (Protected Process Light).'
           Why  = 'Stezuje dump pametiho LSASS a kradez prihlasovacich udaju (mimikatz).'
           Risk = 'Moderate'; Hive = 'HKLM'; Key = 'SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RunAsPPL'; Type = 'DWord'; Value = 1 }

        @{ Id = 'SEC-LSA-ANON'; Cat = 'Zabezpeceni'; Title = 'Omezeni anonymniho vyctu'
           Desc = 'Zakaze anonymni vycet uctu a sdileni.'
           Why  = 'Snizuje mnozstvi informaci, ktere si utocnik vytahne bez prihlaseni.'
           Risk = 'Moderate'; Hive = 'HKLM'; Key = 'SYSTEM\CurrentControlSet\Control\Lsa'; Name = 'RestrictAnonymous'; Type = 'DWord'; Value = 1 }

        @{ Id = 'SEC-PS-SBL'; Cat = 'Zabezpeceni'; Title = 'PowerShell Script Block Logging'
           Desc = 'Zapne logovani obsahu spoustenych PowerShell skriptu.'
           Why  = 'Zasadni pro forenzni analyzu. Nic nerozbije, jen loguje.'
           Risk = 'Safe'; Hive = 'HKLM'; Key = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name = 'EnableScriptBlockLogging'; Type = 'DWord'; Value = 1 }

        @{ Id = 'SEC-RA-OFF'; Cat = 'Zabezpeceni'; Title = 'Vzdalena pomoc vypnuta'
           Desc = 'Zakaze prichozi Vzdalenou pomoc (Remote Assistance).'
           Why  = 'Zmensuje plochu utoku. Bezny domaci user ji stejne nepouziva.'
           Risk = 'Safe'; Hive = 'HKLM'; Key = 'SYSTEM\CurrentControlSet\Control\Remote Assistance'; Name = 'fAllowToGetHelp'; Type = 'DWord'; Value = 0 }

        @{ Id = 'SEC-WSH-OFF'; Cat = 'Zabezpeceni'; Title = 'Windows Script Host vypnuty'
           Desc = 'Zakaze spousteni .vbs/.js skriptu pres Windows Script Host.'
           Why  = 'Klasicky vektor maldoc/priloh. POZOR: nektere legacy instalatory to pouzivaji.'
           Risk = 'Aggressive'; Hive = 'HKLM'; Key = 'SOFTWARE\Microsoft\Windows Script Host\Settings'; Name = 'Enabled'; Type = 'DWord'; Value = 0 }

        # ------------------------------- SOUKROMI -------------------------------
        @{ Id = 'PRIV-TELEMETRY'; Cat = 'Soukromi'; Title = 'Telemetrie na minimum'
           Desc = 'Snizi uroven diagnostickych dat na minimum (Security/Basic).'
           Why  = 'Na Home se neda uplne vynulovat, ale srazi se na minimum. Viz README.'
           Risk = 'Safe'; Hive = 'HKLM'; Key = 'SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry'; Type = 'DWord'; Value = 0 }

        @{ Id = 'PRIV-DIAGTRACK'; Cat = 'Soukromi'; Title = 'Sluzba DiagTrack vypnuta'
           Desc = 'Vypne sluzbu Connected User Experiences and Telemetry (DiagTrack).'
           Why  = 'Hlavni odesilac telemetrie. Vypnuti neovlivni bezne funkce.'
           Risk = 'Safe'; Hive = 'HKLM'; Key = 'SYSTEM\CurrentControlSet\Services\DiagTrack'; Name = 'Start'; Type = 'DWord'; Value = 4 }

        @{ Id = 'PRIV-ADID'; Cat = 'Soukromi'; Title = 'Reklamni ID vypnuto'
           Desc = 'Zakaze reklamni identifikator pro cileni reklam napric aplikacemi.'
           Why  = 'Mene sledovani aktivit uzivatele skrz aplikace.'
           Risk = 'Safe'; Hive = 'HKLM'; Key = 'SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'; Name = 'DisabledByGroupPolicy'; Type = 'DWord'; Value = 1 }

        @{ Id = 'PRIV-ACTFEED'; Cat = 'Soukromi'; Title = 'Historie aktivit vypnuta'
           Desc = 'Vypne sber a odesilani historie aktivit (Timeline).'
           Why  = 'Windows prestane sbirat prehled toho, co uzivatel delal.'
           Risk = 'Safe'; Hive = 'HKLM'; Key = 'SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'EnableActivityFeed'; Type = 'DWord'; Value = 0 }

        @{ Id = 'PRIV-ACTPUB'; Cat = 'Soukromi'; Title = 'Publikovani aktivit vypnuto'
           Desc = 'Zakaze publikovani uzivatelskych aktivit.'
           Why  = 'Doplnuje vypnuti Timeline.'
           Risk = 'Safe'; Hive = 'HKLM'; Key = 'SOFTWARE\Policies\Microsoft\Windows\System'; Name = 'PublishUserActivities'; Type = 'DWord'; Value = 0 }

        @{ Id = 'PRIV-CORTANA'; Cat = 'Soukromi'; Title = 'Cortana vypnuta'
           Desc = 'Zakaze Cortanu.'
           Why  = 'Mene odesilani dotazu a hlasovych dat do cloudu.'
           Risk = 'Safe'; Hive = 'HKLM'; Key = 'SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name = 'AllowCortana'; Type = 'DWord'; Value = 0 }

        @{ Id = 'PRIV-WEBSEARCH'; Cat = 'Soukromi'; Title = 'Webove vysledky ve Startu vypnuty'
           Desc = 'Vypne Bing/webove vysledky v nabidce Start.'
           Why  = 'Hledani ve Startu prestane posilat text do Microsoftu.'
           Risk = 'Moderate'; Hive = 'HKLM'; Key = 'SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Name = 'DisableWebSearch'; Type = 'DWord'; Value = 1 }

        @{ Id = 'PRIV-CONSUMER'; Cat = 'Soukromi'; Title = 'Consumer features vypnuty'
           Desc = 'Zakaze automaticke instalace doporucenych aplikaci a reklamni obsah.'
           Why  = 'Konec tichemu doinstalovavani bloatware a navrhu ve Startu.'
           Risk = 'Safe'; Hive = 'HKLM'; Key = 'SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Name = 'DisableWindowsConsumerFeatures'; Type = 'DWord'; Value = 1 }

        @{ Id = 'PRIV-RECALL'; Cat = 'Soukromi'; Title = 'Windows Recall vypnuto'
           Desc = 'Zakaze AI funkci Recall (periodicke snimky obrazovky).'
           Why  = 'Recall uklada snimky vseho na obrazovce. Pro soukromi zasadni vypnout.'
           Risk = 'Safe'; Hive = 'HKLM'; Key = 'SOFTWARE\Policies\Microsoft\Windows\WindowsAI'; Name = 'DisableAIDataAnalysis'; Type = 'DWord'; Value = 1 }

        @{ Id = 'PRIV-LOCATION'; Cat = 'Soukromi'; Title = 'Polohove sluzby vypnuty'
           Desc = 'Globalne vypne polohove sluzby.'
           Why  = 'Mene sledovani polohy. POZOR: rozbije pocasi, mapy a aplikace podle polohy.'
           Risk = 'Moderate'; Hive = 'HKLM'; Key = 'SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'; Name = 'DisableLocation'; Type = 'DWord'; Value = 1 }

        @{ Id = 'PRIV-WER'; Cat = 'Soukromi'; Title = 'Hlaseni chyb vypnuto'
           Desc = 'Vypne Windows Error Reporting.'
           Why  = 'Prestane odesilat crash dumpy, ktere mohou obsahovat citliva data.'
           Risk = 'Safe'; Hive = 'HKLM'; Key = 'SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'; Name = 'Disabled'; Type = 'DWord'; Value = 1 }

        @{ Id = 'PRIV-EDGE-METRICS'; Cat = 'Soukromi'; Title = 'Edge telemetrie vypnuta'
           Desc = 'Vypne odesilani metrik z prohlizece Edge.'
           Why  = 'Mene dat posilanych z prohlizece.'
           Risk = 'Safe'; Hive = 'HKLM'; Key = 'SOFTWARE\Policies\Microsoft\Edge'; Name = 'MetricsReportingEnabled'; Type = 'DWord'; Value = 0 }

        @{ Id = 'PRIV-EDGE-PERS'; Cat = 'Soukromi'; Title = 'Edge personalizace vypnuta'
           Desc = 'Zakaze personalizaci a reporting v Edge.'
           Why  = 'Omezi profilovani uzivatele prohlizecem.'
           Risk = 'Safe'; Hive = 'HKLM'; Key = 'SOFTWARE\Policies\Microsoft\Edge'; Name = 'PersonalizationReportingEnabled'; Type = 'DWord'; Value = 0 }
    )
}
#endregion

#region ---------------------------------------------------------- Registr
function Get-BaseKey {
    param([string]$Hive)
    switch ($Hive) {
        'HKLM' { [Microsoft.Win32.Registry]::LocalMachine }
        'HKCU' { [Microsoft.Win32.Registry]::CurrentUser }
        default { throw "Neznamy hive: $Hive" }
    }
}

function Get-RegState {
    param([string]$Hive, [string]$Key, [string]$Name)
    $base = Get-BaseKey $Hive
    $result = [ordered]@{ KeyExists = $false; ValueExists = $false; Value = $null; Kind = $null }
    $sub = $base.OpenSubKey($Key, $false)
    if ($sub) {
        $result.KeyExists = $true
        if ($sub.GetValueNames() -contains $Name) {
            $result.ValueExists = $true
            $result.Value = $sub.GetValue($Name)
            $result.Kind  = $sub.GetValueKind($Name).ToString()
        }
        $sub.Close()
    }
    [pscustomobject]$result
}

function Set-RegValue {
    param([string]$Hive, [string]$Key, [string]$Name, $Value, [string]$Type)
    $base = Get-BaseKey $Hive
    $sub  = $base.CreateSubKey($Key)   # vytvori nebo otevre zapisovatelny
    if (-not $sub) { throw "Nepodarilo se otevrit/vytvorit klic $Hive\$Key" }
    $kind = [Microsoft.Win32.RegistryValueKind]::$Type
    $sub.SetValue($Name, (Convert-ByKind $Value $Type), $kind)
    $sub.Close()
}

function Remove-RegValue {
    param([string]$Hive, [string]$Key, [string]$Name)
    $base = Get-BaseKey $Hive
    $sub  = $base.OpenSubKey($Key, $true)
    if ($sub) {
        if ($sub.GetValueNames() -contains $Name) { $sub.DeleteValue($Name, $false) }
        $sub.Close()
    }
}

function Convert-ByKind {
    param($Value, [string]$Type)
    switch ($Type) {
        'DWord'        { return [int]$Value }
        'QWord'        { return [long]$Value }
        'String'       { return [string]$Value }
        'ExpandString' { return [string]$Value }
        'MultiString'  { return [string[]]$Value }
        default        { return $Value }
    }
}

function Test-Compliant {
    param($Rule, $State)
    if (-not $State.ValueExists) { return $false }
    switch ($Rule.Type) {
        'DWord' { return ([int]$State.Value -eq [int]$Rule.Value) }
        'QWord' { return ([long]$State.Value -eq [long]$Rule.Value) }
        default { return ([string]$State.Value -eq [string]$Rule.Value) }
    }
}
#endregion

#region ---------------------------------------------------------- Pomocne
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-EditionId {
    (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).EditionID
}

function Initialize-Dirs {
    foreach ($d in @($script:DataDir, $script:RunsDir, $script:ReportDir)) {
        if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
    }
}

function Write-Head {
    param([string]$Text)
    Write-Host ''
    Write-Host "  $Text" -ForegroundColor Black -BackgroundColor Green
    Write-Host ''
}
#endregion

#region ---------------------------------------------------------- Audit
function Invoke-Audit {
    $rules = Get-HardeningRules
    $results = foreach ($r in $rules) {
        $state = Get-RegState -Hive $r.Hive -Key $r.Key -Name $r.Name
        $ok = Test-Compliant -Rule $r -State $state
        [pscustomobject]@{
            Id        = $r.Id
            Cat       = $r.Cat
            Title     = $r.Title
            Desc      = $r.Desc
            Why       = $r.Why
            Risk      = $r.Risk
            Path      = "$($r.Hive)\$($r.Key)"
            Name      = $r.Name
            Desired   = $r.Value
            Current   = if ($state.ValueExists) { $state.Value } else { '(nenastaveno)' }
            Compliant = $ok
        }
    }
    $results
}
#endregion

#region ---------------------------------------------------------- Harden
function Invoke-Harden {
    param([string]$Tier, [switch]$Yes)

    $maxRank = $script:RiskRank[$Tier]
    $rules = Get-HardeningRules | Where-Object { $script:RiskRank[$_.Risk] -le $maxRank }

    # Zjisti, co se realne zmeni (jen nekompliantni).
    $pending = foreach ($r in $rules) {
        $state = Get-RegState -Hive $r.Hive -Key $r.Key -Name $r.Name
        if (-not (Test-Compliant -Rule $r -State $state)) {
            [pscustomobject]@{ Rule = $r; State = $state }
        }
    }

    if (-not $pending) {
        Write-Host 'Vse uz je v pozadovanem stavu, neni co menit.' -ForegroundColor Green
        return
    }

    Write-Head "Zmeni se $($pending.Count) nastaveni (uroven: $Tier)"
    $pending | ForEach-Object {
        $flag = switch ($_.Rule.Risk) { 'Safe' {'[OK]'} 'Moderate' {'[!]'} 'Aggressive' {'[!!]'} }
        Write-Host ("  {0,-4} {1,-22} {2}" -f $flag, $_.Rule.Id, $_.Rule.Title)
    }
    Write-Host ''
    Write-Host '  [!] muze ovlivnit nektere funkce, [!!] agresivni - precti si popis.' -ForegroundColor Yellow
    Write-Host ''

    if (-not $Yes) {
        $ans = Read-Host 'Pokracovat? Napis ANO'
        if ($ans -ne 'ANO') { Write-Host 'Zruseno.' -ForegroundColor Yellow; return }
    }

    # Bod obnoveni systemu (best-effort).
    $restorePoint = $false
    try {
        Checkpoint-Computer -Description 'BOIT Harden Home' -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        $restorePoint = $true
        Write-Host 'Vytvoren bod obnoveni systemu.' -ForegroundColor DarkGray
    } catch {
        Write-Host 'Bod obnoveni se nepodarilo vytvorit (muze byt vypnuty nebo casovy limit). Revert log stejne vznikne.' -ForegroundColor Yellow
    }

    $changes = @()
    foreach ($p in $pending) {
        $r = $p.Rule; $s = $p.State
        try {
            Set-RegValue -Hive $r.Hive -Key $r.Key -Name $r.Name -Value $r.Value -Type $r.Type
            $changes += [pscustomobject]@{
                Id    = $r.Id
                Title = $r.Title
                Hive  = $r.Hive
                Key   = $r.Key
                Name  = $r.Name
                Type  = $r.Type
                Prior = [pscustomobject]@{
                    KeyExists   = $s.KeyExists
                    ValueExists = $s.ValueExists
                    Value       = $s.Value
                    Kind        = $s.Kind
                }
                New = [pscustomobject]@{ Value = $r.Value; Type = $r.Type }
            }
            Write-Host ("  zmeneno: {0}" -f $r.Id) -ForegroundColor Green
        } catch {
            Write-Host ("  CHYBA u {0}: {1}" -f $r.Id, $_.Exception.Message) -ForegroundColor Red
        }
    }

    if (-not $changes) { Write-Host 'Nic se nezmenilo.' -ForegroundColor Yellow; return }

    # Transakcni log pro revert.
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $runObj = [pscustomobject]@{
        App          = $script:AppName
        Timestamp    = (Get-Date).ToString('s')
        Tier         = $Tier
        Machine      = $env:COMPUTERNAME
        EditionId    = Get-EditionId
        RestorePoint = $restorePoint
        Reverted     = $false
        Changes      = $changes
    }
    $runPath = Join-Path $script:RunsDir "run-$stamp.json"
    $runObj | ConvertTo-Json -Depth 8 | Set-Content -Path $runPath -Encoding UTF8

    Write-Host ''
    Write-Host "Hotovo. Zmeneno: $($changes.Count). Log: $runPath" -ForegroundColor Green
    Write-Host "Revert kdykoliv:  .\Invoke-BoitHardenHome.ps1 -Mode Revert" -ForegroundColor Cyan

    $report = New-HtmlReport -Title "Harden - beh $stamp" -Audit (Invoke-Audit)
    Write-Host "Report: $report" -ForegroundColor Cyan
}
#endregion

#region ---------------------------------------------------------- Revert
function Get-LatestRun {
    Get-ChildItem -Path $script:RunsDir -Filter 'run-*.json' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 1
}

function Invoke-Revert {
    param([string]$RunFile, [switch]$Yes)

    $file = $null
    if ($RunFile) {
        if (-not (Test-Path $RunFile)) { throw "Soubor neexistuje: $RunFile" }
        $file = Get-Item $RunFile
    } else {
        $file = Get-LatestRun
        if (-not $file) { Write-Host 'Zadny beh k vraceni.' -ForegroundColor Yellow; return }
    }

    $run = Get-Content $file.FullName -Raw | ConvertFrom-Json
    if ($run.Reverted) {
        Write-Host 'Tenhle beh uz byl vracen.' -ForegroundColor Yellow
        if (-not $Yes) { $a = Read-Host 'Presto vratit znovu? ANO'; if ($a -ne 'ANO') { return } }
    }

    Write-Head "Revert behu z $($run.Timestamp) ($($run.Changes.Count) zmen)"
    $run.Changes | ForEach-Object { Write-Host ("  {0,-22} {1}" -f $_.Id, $_.Title) }
    Write-Host ''
    if (-not $Yes) {
        $ans = Read-Host 'Vratit vsechny tyto zmeny? Napis ANO'
        if ($ans -ne 'ANO') { Write-Host 'Zruseno.' -ForegroundColor Yellow; return }
    }

    # Vraceni v opacnem poradi.
    $ordered = @($run.Changes)
    [array]::Reverse($ordered)
    foreach ($c in $ordered) {
        try {
            if ($c.Prior.ValueExists) {
                Set-RegValue -Hive $c.Hive -Key $c.Key -Name $c.Name -Value $c.Prior.Value -Type $c.Prior.Kind
                Write-Host ("  obnoveno: {0}" -f $c.Id) -ForegroundColor Green
            } else {
                Remove-RegValue -Hive $c.Hive -Key $c.Key -Name $c.Name
                # Kdyz jsme klic vytvorili my a je prazdny, uklid.
                if (-not $c.Prior.KeyExists) {
                    $base = Get-BaseKey $c.Hive
                    $sub = $base.OpenSubKey($c.Key, $false)
                    if ($sub -and $sub.ValueCount -eq 0 -and $sub.SubKeyCount -eq 0) {
                        $sub.Close()
                        try { $base.DeleteSubKey($c.Key, $false) } catch {}
                    } elseif ($sub) { $sub.Close() }
                }
                Write-Host ("  smazano (nebylo puvodne): {0}" -f $c.Id) -ForegroundColor Green
            }
        } catch {
            Write-Host ("  CHYBA u {0}: {1}" -f $c.Id, $_.Exception.Message) -ForegroundColor Red
        }
    }

    $run.Reverted = $true
    $run | ConvertTo-Json -Depth 8 | Set-Content -Path $file.FullName -Encoding UTF8
    Write-Host ''
    Write-Host 'Revert hotovy. Nektere zmeny (napr. sluzby) se projevi po restartu.' -ForegroundColor Green
}
#endregion

#region ---------------------------------------------------------- Report (BOIT)
function New-HtmlReport {
    param([string]$Title, $Audit)

    $okCount   = @($Audit | Where-Object Compliant).Count
    $failCount = @($Audit | Where-Object { -not $_.Compliant }).Count
    $total     = @($Audit).Count

    $rows = foreach ($a in ($Audit | Sort-Object Cat, Id)) {
        $cls = if ($a.Compliant) { 'ok' } else { 'fail' }
        $st  = if ($a.Compliant) { 'OK' } else { 'FUCK UP' }
        $riskCls = switch ($a.Risk) { 'Safe' {'r-safe'} 'Moderate' {'r-mod'} 'Aggressive' {'r-agg'} }
@"
<tr class="$cls">
  <td class="st">$st</td>
  <td><span class="rid">$($a.Id)</span><br><b>$([System.Web.HttpUtility]::HtmlEncode($a.Title))</b>
      <div class="desc">$([System.Web.HttpUtility]::HtmlEncode($a.Desc))</div>
      <div class="why">$([System.Web.HttpUtility]::HtmlEncode($a.Why))</div></td>
  <td class="$riskCls">$($a.Risk)</td>
  <td class="mono">$([System.Web.HttpUtility]::HtmlEncode([string]$a.Current))</td>
  <td class="mono">$([System.Web.HttpUtility]::HtmlEncode([string]$a.Desired))</td>
</tr>
"@
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $date  = Get-Date -Format 'd. M. yyyy HH:mm'
    $html = @"
<!DOCTYPE html>
<html lang="cs"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$Title</title>
<style>
  :root{ --lime:#$($script:Lime); --bg:#0a0b0d; --card:#15171b; --line:#262a30; --mut:#8a929c; }
  *{box-sizing:border-box} body{margin:0;background:var(--bg);color:#e8ebee;
    font-family:ui-sans-serif,Segoe UI,Roboto,Arial,sans-serif;line-height:1.5;padding:24px}
  .wrap{max-width:1100px;margin:0 auto}
  h1{font-family:ui-monospace,Consolas,monospace;font-size:22px;margin:0 0 4px}
  .sub{color:var(--mut);font-size:13px;margin-bottom:24px}
  .cards{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}
  .c{background:var(--card);border:1px solid var(--line);padding:16px 20px;min-width:140px;
     clip-path:polygon(0 0,100% 0,100% 100%,12px 100%,0 calc(100% - 12px))}
  .c .n{font-size:30px;font-weight:700;font-family:ui-monospace,monospace}
  .c .l{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.06em}
  .c.good .n{color:var(--lime)} .c.bad .n{color:#ff5a5a}
  table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line)}
  th{background:#101216;text-align:left;padding:10px 12px;font-size:12px;text-transform:uppercase;
     letter-spacing:.05em;color:var(--mut);border-bottom:1px solid var(--line)}
  td{padding:12px;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}
  .st{font-weight:700;font-family:ui-monospace,monospace;white-space:nowrap}
  tr.ok .st{color:var(--lime)} tr.fail .st{color:#ff5a5a}
  .rid{font-family:ui-monospace,monospace;font-size:11px;color:var(--mut)}
  .desc{color:#cfd4da;font-size:13px;margin-top:4px}
  .why{color:var(--mut);font-size:12px;margin-top:2px;font-style:italic}
  .mono{font-family:ui-monospace,monospace;font-size:13px}
  .r-safe{color:var(--lime)} .r-mod{color:#ffc24b} .r-agg{color:#ff7a45}
  footer{color:var(--mut);font-size:12px;margin-top:24px;text-align:center}
  .tag{color:var(--lime);font-weight:700}
</style></head>
<body><div class="wrap">
  <h1>$([System.Web.HttpUtility]::HtmlEncode($Title))</h1>
  <div class="sub">$date &nbsp;&middot;&nbsp; $env:COMPUTERNAME &nbsp;&middot;&nbsp; $(Get-EditionId)</div>
  <div class="cards">
    <div class="c good"><div class="n">$okCount</div><div class="l">V&nbsp;poradku</div></div>
    <div class="c bad"><div class="n">$failCount</div><div class="l">K&nbsp;naprave</div></div>
    <div class="c"><div class="n">$total</div><div class="l">Celkem kontrol</div></div>
  </div>
  <table>
    <thead><tr><th>Stav</th><th>Kontrola</th><th>Riziko</th><th>Aktualne</th><th>Cil</th></tr></thead>
    <tbody>
    $($rows -join "`n")
    </tbody>
  </table>
  <footer>BOIT Harden Home &nbsp;&middot;&nbsp; Delame <span class="tag">#BezpecnejsiCesko</span></footer>
</div></body></html>
"@
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    $path = Join-Path $script:ReportDir "report-$stamp.html"
    $html | Set-Content -Path $path -Encoding UTF8
    return $path
}
#endregion

#region ---------------------------------------------------------- Menu
function Show-Menu {
    Write-Head $script:AppName
    Write-Host '  1) Audit    - jen zkontrolovat (nic nemeni) + HTML report'
    Write-Host '  2) Harden   - aplikovat zmeny (s moznosti revertu)'
    Write-Host '  3) Revert   - vratit posledni beh zpatky'
    Write-Host '  4) Konec'
    Write-Host ''
    Read-Host 'Volba'
}

function Start-App {
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    Initialize-Dirs

    if (-not (Test-Admin)) {
        Write-Host 'Spust jako administrator (jinak nepujde zapsat do HKLM).' -ForegroundColor Red
        return
    }

    switch ($Mode) {
        'Audit'  { $a = Invoke-Audit; $p = New-HtmlReport -Title 'Audit zabezpeceni' -Audit $a
                   $a | Select-Object Id, Title, Risk, Compliant | Format-Table -AutoSize
                   Write-Host "Report: $p" -ForegroundColor Cyan; return }
        'Harden' { Invoke-Harden -Tier $Tier -Yes:$Yes; return }
        'Revert' { Invoke-Revert -RunFile $RunFile -Yes:$Yes; return }
    }

    # Interaktivni menu
    do {
        $c = Show-Menu
        switch ($c) {
            '1' { $a = Invoke-Audit; $p = New-HtmlReport -Title 'Audit zabezpeceni' -Audit $a
                  $a | Select-Object Id, Title, Risk, Compliant | Format-Table -AutoSize
                  Write-Host "Report: $p" -ForegroundColor Cyan }
            '2' {
                  Write-Host ''
                  Write-Host '  Uroven:  1) Safe   2) Safe+Moderate   3) Vse (vcetne agresivnich)'
                  $t = Read-Host '  Volba'
                  $tier = switch ($t) { '1' {'Safe'} '2' {'Moderate'} '3' {'Aggressive'} default {'Safe'} }
                  Invoke-Harden -Tier $tier
                }
            '3' { Invoke-Revert }
            '4' { return }
            default { Write-Host 'Neplatna volba.' -ForegroundColor Yellow }
        }
    } while ($true)
}
#endregion

Start-App
