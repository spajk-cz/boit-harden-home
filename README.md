# BOIT Harden Home

**Zkontrolujte a vylepšete bezpečnost a soukromí svého Windows – jedním klikem, česky, a kdykoli se to dá vrátit zpět.**

BOIT Harden Home projde nastavení vašeho Windows 11 (funguje i na Windows 10), česky vysvětlí, co je v pořádku a co by šlo zabezpečit lépe, a nechá vás vybrat, co chcete změnit. Nic se nestane bez vašeho souhlasu a každá změna jde vrátit do původního stavu.

> Děláme **#BezpečnějšíČesko**

---

## ⬇️ Stáhnout

**[Stáhnout nejnovější verzi (.exe)](https://github.com/spajk-cz/boit-harden-home/releases/latest)**

1. Na stránce vydání (Releases) klikněte na soubor **`BoitHardenHome.exe`**.
2. Soubor spusťte. Není potřeba nic instalovat – je to jediný soubor.
3. Windows se zeptá na oprávnění správce (aplikace mění systémová nastavení) – potvrďte **Ano**.

> **Windows hlásí „neznámý vydavatel"?** To je normální u aplikací bez placeného podpisu. Klikněte na **Další informace → Přesto spustit**. Aplikace je otevřená, celý její kód si můžete prohlédnout přímo tady v repozitáři.

---

## Co to umí

Aplikace vás provede třemi kroky:

1. **Kontrola** – projede systém a ukáže přehledně, co je v pořádku a co k nápravě.
2. **Náprava** – vyberete, co chcete změnit (vše je česky vysvětlené, včetně toho, proč na tom záleží), a potvrdíte.
3. **Vrácení** – kdykoli můžete všechny změny vrátit přesně do stavu před spuštěním.

Každé doporučení má barevné označení rizika:

- 🟢 **Bezpečné** – nerozbije žádné funkce, jen zavře zbytečné díry a omezí sledování.
- 🟡 **Střední** – může mírně ovlivnit chování systému (např. více bezpečnostních dotazů).
- 🟠 **Agresivní** – tvrdší změny, které mohou vadit starším aplikacím. U každé je to napsané.

## Co konkrétně kontroluje

**Bezpečnost:** Řízení uživatelských účtů (UAC), SmartScreen, automatické spouštění médií, zastaralý protokol SMBv1, LLMNR, ochrana přihlašovacích údajů (LSASS), logování Powershellu, Windows Script Host a další.

**Soukromí:** telemetrie a diagnostická data, reklamní ID, historie aktivit, Cortana, **Windows Recall**, polohové služby, hlášení chyb, telemetrie prohlížeče Edge a další.

## Jak funguje vrácení změn

Tohle je srdce aplikace. **Žádná změna se neprovede bez toho, aby se napřed uložil přesný původní stav.** Před každou úpravou aplikace:

- vytvoří **bod obnovení systému**,
- uloží si do lokálního záznamu přesnou původní hodnotu každého nastavení.

Když si to pak rozmyslíte, v aplikaci kliknete na **„Vrátit změny…"**, vyberete příslušný běh a vše se obnoví do stavu před spuštěním. Záznamy o změnách najdete v `%ProgramData%\BOIT-Harden\runs\`.

## Dobré vědět

- Na edici **Windows Home** nejde telemetrii vypnout úplně (plně to umí jen Pro/Enterprise/Education) – aplikace ji srazí na minimum.
- Některé změny (např. služby) se projeví až **po restartu**.
- Aplikaci si nejdřív vyzkoušejte, než ji nasadíte na důležitý počítač. Od toho je tam vrácení změn a bod obnovení.

---

## Licence

MIT – viz [LICENSE](LICENSE). Otevřený kód, můžete si ho prohlédnout i upravit.

---

<details>
<summary>Pro vývojáře (build ze zdrojáků)</summary>

Repozitář obsahuje grafickou aplikaci (`gui/`, WPF / .NET 8) i PowerShell variantu se stejným jádrem (`src/Invoke-BoitHardenHome.ps1`).

Hotový `.exe` vzniká automaticky přes GitHub Actions (`.github/workflows/build.yml`) – každý push ho vystaví jako artifact, tag `v*` z něj udělá veřejný Release.

Lokální build (potřebujete .NET 8 SDK):

```powershell
dotnet publish gui\BoitHardenHome.csproj -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o publish
# výsledek: publish\BoitHardenHome.exe
```

Vydání nové verze:

```bash
git tag v0.2.0
git push origin v0.2.0   # spustí build a publikaci Release s .exe
```

</details>
