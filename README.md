# BOIT Harden Home

Interaktivní **hardening & privacy audit** nástroj pro domácí Windows 11 (funguje i na Windows 10). Projde nastavení systému, česky vysvětlí, co je špatně, a nabídne nápravu – **s plnohodnotným revertem zpátky do původního stavu**.

Přichází ve dvou podobách:

- **`gui/`** – grafická aplikace (`BoitHardenHome.exe`) pro běžného uživatele. Dvojklik, česky, žádný PowerShell. **Tohle chceš dát lidem.**
- **`src/`** – PowerShell skript pro power usery a automatizaci (stejný engine).

> Děláme **#BezpečnějšíČesko**

---

## Co to dělá

Tři režimy:

| Režim    | Co dělá                                                                  |
|----------|--------------------------------------------------------------------------|
| `Audit`  | Jen čte, nic nemění. Vyplivne HTML report (co je OK / co je k nápravě).  |
| `Harden` | Aplikuje změny podle zvolené úrovně rizika. Před každou změnou zazálohuje původní stav. |
| `Revert` | Vrátí změny z vybraného (nebo posledního) běhu přesně do původního stavu. |

Pravidla pokrývají dvě roviny:

- **Zabezpečení** – UAC, SmartScreen, AutoRun, SMBv1, LLMNR, ochrana LSASS, PowerShell logging, Windows Script Host a další.
- **Soukromí** – telemetrie, DiagTrack, reklamní ID, historie aktivit, Cortana, Recall, polohové služby, Edge telemetrie atd.

Zdroj pravidel je rozumná podmnožina **Microsoft Security Baseline** a **CIS Benchmarku** (profil pro standalone/domácí stanici), doplněná o privacy vrstvu inspirovanou přístupem privacy.sexy.

---

## Jak to funguje s revertem (důležité)

Celý engine je postavený tak, že **změnu nelze provést bez zálohy původního stavu**. Při každém `Harden` běhu vznikne transakční log:

```
%ProgramData%\BOIT-Harden\runs\run-RRRRMMDD-HHMMSS.json
```

Pro každou změněnou hodnotu se uloží:

- jestli klíč a hodnota předtím existovaly,
- přesná původní hodnota a její typ.

Revert pak jede log v opačném pořadí:

- hodnota **předtím existovala** → nastaví se zpět původní hodnota a typ,
- hodnota **předtím neexistovala** → hodnota se smaže (a pokud klíč vytvořil tento nástroj a zůstal prázdný, smaže se i klíč).

Navíc se před aplikací (best-effort) vytvoří **bod obnovení systému**.

Takže když si to někdo rozmyslí, nebo bude mít podezření, že mu něco rozbil tenhle nástroj, má dvě cesty: projet si audit/report, co se změnilo, a pak jedním příkazem všechno vrátit.

---

## GUI aplikace (`BoitHardenHome.exe`)

Pro běžného uživatele. WPF aplikace na **.NET 8**, kompilovaná jako **jednosouborový self-contained `.exe`** – uživatel nemusí nic instalovat, jen dvojklik. Aplikace si přes UAC řekne o práva administrátora, projede kontrolu a ukáže česky, co je v pořádku a co k nápravě. Uživatel zaškrtá, co chce, klikne „Použít vybrané“ a hotovo. Tlačítko **„Vrátit změny…“** nabídne všechny předchozí běhy k vrácení.

### Jak získat .exe

**Varianta A – přes GitHub Actions (bez instalace čehokoli):**
Po pushnutí na `main` se workflow `.github/workflows/build.yml` spustí na Windows runneru a vybuilděný `BoitHardenHome.exe` je ke stažení jako artifact (záložka Actions → běh → Artifacts).

**Varianta B – lokální build (potřebuješ .NET 8 SDK):**
```powershell
dotnet publish gui\BoitHardenHome.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish
# výsledek: publish\BoitHardenHome.exe
```

> Pozn.: jednosouborový self-contained build má cca 150 MB (obsahuje celý .NET runtime). Když chceš menší, dej `--self-contained false` – pak ale uživatel potřebuje nainstalovaný .NET 8 Desktop Runtime.

---

## PowerShell skript (`src/`)

PowerShell **jako administrátor** (zápis do HKLM):

```powershell
# Interaktivní menu
.\src\Invoke-BoitHardenHome.ps1

# Jen audit + HTML report
.\src\Invoke-BoitHardenHome.ps1 -Mode Audit

# Hardening - bezpečná úroveň
.\src\Invoke-BoitHardenHome.ps1 -Mode Harden -Tier Safe

# Hardening bez interaktivního potvrzení (pro testy na VM)
.\src\Invoke-BoitHardenHome.ps1 -Mode Harden -Tier Moderate -Yes

# Revert posledního běhu
.\src\Invoke-BoitHardenHome.ps1 -Mode Revert

# Revert konkrétního běhu
.\src\Invoke-BoitHardenHome.ps1 -Mode Revert -RunFile "C:\ProgramData\BOIT-Harden\runs\run-20260101-120000.json"
```

Pokud je `ExecutionPolicy` v cestě:

```powershell
powershell -ExecutionPolicy Bypass -File .\src\Invoke-BoitHardenHome.ps1
```

### Úrovně rizika

- **Safe** – nerozbíjí funkce, jen zavírá zbytečné díry a telemetrii.
- **Moderate** – může ovlivnit chování (víc UAC dotazů, vypnuté webové hledání ve Startu, polohové služby).
- **Aggressive** – tvrdé věci (např. vypnutý Windows Script Host), které mohou vadit legacy software.

Vyšší úroveň vždy zahrnuje nižší.

---

## Omezení, se kterými počítej

- **Windows Home nevynuluje telemetrii úplně** – `AllowTelemetry=0` plně respektuje jen Enterprise/Education. Na Home to srazíme na minimum a navíc vypneme službu DiagTrack, ale „čistá nula" to není.
- **Tamper Protection Defenderu nejde zapnout skriptem** – to je schválně. Nástroj na to umí jen upozornit.
- **Edge Application Guard už neexistuje** – Microsoft ho deprecoval a od Windows 11 24H2 odstranil. Pro izolaci používej **Windows Sandbox** nebo Edge Enhanced Security Mode.
- Některé změny (služby) se projeví až **po restartu**.
- HKCU pravidla by platila jen pro aktuálního uživatele; verze zatím cílí na HKLM (platí pro celý stroj).

---

## Roadmap

- [ ] Engine pro ne-registrová pravidla s vlastní capture/revert logikou (ASR pravidla, Defender `Set-MpPreference`, sloužby přes `Set-Service`).
- [ ] Detekce driftu po Windows Update (přeskenovat a nahlásit, co update vrátil zpátky).
- [ ] Externí soubor pravidel (`rules.psd1`/JSON) místo vestavěných.
- [x] GUI (WPF) nad stejným enginem → `gui/`.
- [ ] Podpis `.exe` (code signing certifikát), ať SmartScreen neřve.
- [ ] HTML report i z GUI.

---

## Varování

Nástroj mění systémové nastavení. **Nejdřív otestuj na virtuálce.** Autor nenese odpovědnost za rozbité prostředí – od toho je ten revert a bod obnovení.

## Licence

MIT – viz [LICENSE](LICENSE).
