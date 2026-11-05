namespace BoitHardenHome.Engine;

public static class Rules
{
    public static List<Rule> All() => new()
    {
        // =============================== ZABEZPEČENÍ ===============================
        new Rule { Id="SEC-UAC-ENABLE", Cat="Zabezpečení", Title="Zapnout Řízení uživatelských účtů (UAC)",
            Desc="Zajistí, že je UAC zapnuté.",
            Why="Bez UAC běží aplikace rovnou s plnými právy – ráj pro malware.",
            Risk="Safe", Hive="HKLM", Key=@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", Name="EnableLUA", Type="DWord", Value=1 },

        new Rule { Id="SEC-UAC-SECUREDESKTOP", Cat="Zabezpečení", Title="UAC dotaz na zabezpečené ploše",
            Desc="UAC dotaz se zobrazí na zatmavené zabezpečené ploše.",
            Why="Aplikace nemůže dotaz předstírat ani odklikat za uživatele.",
            Risk="Safe", Hive="HKLM", Key=@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", Name="PromptOnSecureDesktop", Type="DWord", Value=1 },

        new Rule { Id="SEC-UAC-ADMINPROMPT", Cat="Zabezpečení", Title="UAC vždy vyžadovat souhlas",
            Desc="U akcí s vyššími právy je administrátor vždy dotázán na souhlas.",
            Why="Ztěžuje tichou eskalaci oprávnění. Cena je o něco víc dotazů.",
            Risk="Moderate", Hive="HKLM", Key=@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", Name="ConsentPromptBehaviorAdmin", Type="DWord", Value=2 },

        new Rule { Id="SEC-SMARTSCREEN-ON", Cat="Zabezpečení", Title="Zapnout SmartScreen",
            Desc="Kontroluje stahované soubory a spouštěné aplikace přes SmartScreen.",
            Why="Blokuje známý škodlivý a nedůvěryhodný obsah ještě před spuštěním.",
            Risk="Safe", Hive="HKLM", Key=@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", Name="EnableSmartScreen", Type="DWord", Value=1 },

        new Rule { Id="SEC-SMARTSCREEN-BLOCK", Cat="Zabezpečení", Title="SmartScreen na úrovni Blokovat",
            Desc="Nedůvěryhodný obsah SmartScreen rovnou zablokuje.",
            Why="Režim pouhého varování se dá odklikat; Blokovat je tvrdší.",
            Risk="Moderate", Hive="HKLM", Key=@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", Name="ShellSmartScreenLevel", Type="String", Value="Block" },

        new Rule { Id="SEC-AUTORUN-OFF", Cat="Zabezpečení", Title="Vypnout automatické spouštění médií",
            Desc="Vypne AutoRun/AutoPlay pro všechny typy jednotek.",
            Why="Klasický vektor šíření přes USB. Žádné auto-spuštění z média.",
            Risk="Safe", Hive="HKLM", Key=@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", Name="NoDriveTypeAutoRun", Type="DWord", Value=255 },

        new Rule { Id="SEC-INSTALLER-ELEV", Cat="Zabezpečení", Title="Zakázat AlwaysInstallElevated",
            Desc="Zakáže instalaci MSI balíčků automaticky s právy systému.",
            Why="Zapnuté AlwaysInstallElevated je učebnicová cesta k eskalaci oprávnění.",
            Risk="Safe", Hive="HKLM", Key=@"SOFTWARE\Policies\Microsoft\Windows\Installer", Name="AlwaysInstallElevated", Type="DWord", Value=0 },

        new Rule { Id="SEC-SMB1-SERVER", Cat="Zabezpečení", Title="Vypnout SMBv1 (server)",
            Desc="Vypne zastaralý protokol SMBv1 na straně serveru.",
            Why="SMBv1 je mrtvý a děravý (EternalBlue a spol.). Nemá co dělat na sdílení.",
            Risk="Safe", Hive="HKLM", Key=@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", Name="SMB1", Type="DWord", Value=0 },

        new Rule { Id="SEC-LLMNR-OFF", Cat="Zabezpečení", Title="Vypnout LLMNR",
            Desc="Vypne multicastové rozlišování jmen LLMNR.",
            Why="LLMNR je oblíbený MITM vektor (Responder) pro krádež hashů.",
            Risk="Moderate", Hive="HKLM", Key=@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", Name="EnableMulticast", Type="DWord", Value=0 },

        new Rule { Id="SEC-LSA-PPL", Cat="Zabezpečení", Title="Ochrana LSASS (RunAsPPL)",
            Desc="Spustí proces LSASS jako chráněný (Protected Process Light).",
            Why="Stěžuje dump paměti LSASS a krádež přihlašovacích údajů (mimikatz).",
            Risk="Moderate", Hive="HKLM", Key=@"SYSTEM\CurrentControlSet\Control\Lsa", Name="RunAsPPL", Type="DWord", Value=1 },

        new Rule { Id="SEC-LSA-ANON", Cat="Zabezpečení", Title="Omezit anonymní výčet",
            Desc="Zakáže anonymní výčet účtů a sdílení.",
            Why="Sníží množství informací, které si útočník vytáhne bez přihlášení.",
            Risk="Moderate", Hive="HKLM", Key=@"SYSTEM\CurrentControlSet\Control\Lsa", Name="RestrictAnonymous", Type="DWord", Value=1 },

        new Rule { Id="SEC-PS-SBL", Cat="Zabezpečení", Title="PowerShell Script Block Logging",
            Desc="Zapne logování obsahu spouštěných PowerShell skriptů.",
            Why="Zásadní pro forenzní analýzu. Nic nerozbije, jen loguje.",
            Risk="Safe", Hive="HKLM", Key=@"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", Name="EnableScriptBlockLogging", Type="DWord", Value=1 },

        new Rule { Id="SEC-RA-OFF", Cat="Zabezpečení", Title="Vypnout Vzdálenou pomoc",
            Desc="Zakáže příchozí Vzdálenou pomoc (Remote Assistance).",
            Why="Zmenšuje plochu útoku. Běžný domácí uživatel ji stejně nepoužívá.",
            Risk="Safe", Hive="HKLM", Key=@"SYSTEM\CurrentControlSet\Control\Remote Assistance", Name="fAllowToGetHelp", Type="DWord", Value=0 },

        new Rule { Id="SEC-WSH-OFF", Cat="Zabezpečení", Title="Vypnout Windows Script Host",
            Desc="Zakáže spouštění .vbs/.js skriptů přes Windows Script Host.",
            Why="Klasický vektor škodlivých příloh. POZOR: některé legacy instalátory ho používají.",
            Risk="Aggressive", Hive="HKLM", Key=@"SOFTWARE\Microsoft\Windows Script Host\Settings", Name="Enabled", Type="DWord", Value=0 },

        // ================================ SOUKROMÍ ================================
        new Rule { Id="PRIV-TELEMETRY", Cat="Soukromí", Title="Telemetrie na minimum",
            Desc="Sníží úroveň diagnostických dat na minimum.",
            Why="Na Home se nedá úplně vynulovat, ale srazí se na minimum.",
            Risk="Safe", Hive="HKLM", Key=@"SOFTWARE\Policies\Microsoft\Windows\DataCollection", Name="AllowTelemetry", Type="DWord", Value=0 },

        new Rule { Id="PRIV-DIAGTRACK", Cat="Soukromí", Title="Vypnout službu telemetrie (DiagTrack)",
            Desc="Vypne službu Connected User Experiences and Telemetry.",
            Why="Hlavní odesílač telemetrie. Vypnutí neovlivní běžné funkce.",
            Risk="Safe", Hive="HKLM", Key=@"SYSTEM\CurrentControlSet\Services\DiagTrack", Name="Start", Type="DWord", Value=4 },

        new Rule { Id="PRIV-ADID", Cat="Soukromí", Title="Vypnout reklamní ID",
            Desc="Zakáže reklamní identifikátor pro cílení reklam napříč aplikacemi.",
            Why="Méně sledování aktivit uživatele skrz aplikace.",
            Risk="Safe", Hive="HKLM", Key=@"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo", Name="DisabledByGroupPolicy", Type="DWord", Value=1 },

        new Rule { Id="PRIV-ACTFEED", Cat="Soukromí", Title="Vypnout historii aktivit",
            Desc="Vypne sběr historie aktivit (Timeline).",
            Why="Windows přestane sbírat přehled toho, co uživatel dělal.",
            Risk="Safe", Hive="HKLM", Key=@"SOFTWARE\Policies\Microsoft\Windows\System", Name="EnableActivityFeed", Type="DWord", Value=0 },

        new Rule { Id="PRIV-ACTPUB", Cat="Soukromí", Title="Vypnout publikování aktivit",
            Desc="Zakáže publikování uživatelských aktivit.",
            Why="Doplňuje vypnutí Timeline.",
            Risk="Safe", Hive="HKLM", Key=@"SOFTWARE\Policies\Microsoft\Windows\System", Name="PublishUserActivities", Type="DWord", Value=0 },

        new Rule { Id="PRIV-CORTANA", Cat="Soukromí", Title="Vypnout Cortanu",
            Desc="Zakáže Cortanu.",
            Why="Méně odesílání dotazů a hlasových dat do cloudu.",
            Risk="Safe", Hive="HKLM", Key=@"SOFTWARE\Policies\Microsoft\Windows\Windows Search", Name="AllowCortana", Type="DWord", Value=0 },

        new Rule { Id="PRIV-WEBSEARCH", Cat="Soukromí", Title="Vypnout webové výsledky ve Startu",
            Desc="Vypne Bing/webové výsledky v nabídce Start.",
            Why="Hledání ve Startu přestane posílat text do Microsoftu.",
            Risk="Moderate", Hive="HKLM", Key=@"SOFTWARE\Policies\Microsoft\Windows\Windows Search", Name="DisableWebSearch", Type="DWord", Value=1 },

        new Rule { Id="PRIV-CONSUMER", Cat="Soukromí", Title="Vypnout doporučený obsah a bloatware",
            Desc="Zakáže automatické instalace doporučených aplikací a reklamní obsah.",
            Why="Konec tichému doinstalovávání bloatware a návrhů ve Startu.",
            Risk="Safe", Hive="HKLM", Key=@"SOFTWARE\Policies\Microsoft\Windows\CloudContent", Name="DisableWindowsConsumerFeatures", Type="DWord", Value=1 },

        new Rule { Id="PRIV-RECALL", Cat="Soukromí", Title="Vypnout Windows Recall",
            Desc="Zakáže AI funkci Recall (periodické snímky obrazovky).",
            Why="Recall ukládá snímky všeho na obrazovce. Pro soukromí zásadní vypnout.",
            Risk="Safe", Hive="HKLM", Key=@"SOFTWARE\Policies\Microsoft\Windows\WindowsAI", Name="DisableAIDataAnalysis", Type="DWord", Value=1 },

        new Rule { Id="PRIV-LOCATION", Cat="Soukromí", Title="Vypnout polohové služby",
            Desc="Globálně vypne polohové služby.",
            Why="Méně sledování polohy. POZOR: rozbije počasí, mapy a aplikace podle polohy.",
            Risk="Moderate", Hive="HKLM", Key=@"SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors", Name="DisableLocation", Type="DWord", Value=1 },

        new Rule { Id="PRIV-WER", Cat="Soukromí", Title="Vypnout hlášení chyb",
            Desc="Vypne Windows Error Reporting.",
            Why="Přestane odesílat crash dumpy, které mohou obsahovat citlivá data.",
            Risk="Safe", Hive="HKLM", Key=@"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting", Name="Disabled", Type="DWord", Value=1 },

        new Rule { Id="PRIV-EDGE-METRICS", Cat="Soukromí", Title="Vypnout telemetrii Edge",
            Desc="Vypne odesílání metrik z prohlížeče Edge.",
            Why="Méně dat posílaných z prohlížeče.",
            Risk="Safe", Hive="HKLM", Key=@"SOFTWARE\Policies\Microsoft\Edge", Name="MetricsReportingEnabled", Type="DWord", Value=0 },

        new Rule { Id="PRIV-EDGE-PERS", Cat="Soukromí", Title="Vypnout personalizaci Edge",
            Desc="Zakáže personalizaci a reporting v Edge.",
            Why="Omezí profilování uživatele prohlížečem.",
            Risk="Safe", Hive="HKLM", Key=@"SOFTWARE\Policies\Microsoft\Edge", Name="PersonalizationReportingEnabled", Type="DWord", Value=0 },
    };
}
