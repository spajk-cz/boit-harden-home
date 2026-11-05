namespace BoitHardenHome.Engine;

/// <summary>Jedno pravidlo = jedna registrova hodnota, kterou umime zkontrolovat i nastavit.</summary>
public class Rule
{
    public string Id { get; set; }
    public string Cat { get; set; }      // "Zabezpečení" / "Soukromí"
    public string Title { get; set; }
    public string Desc { get; set; }     // co to dela (CZ)
    public string Why { get; set; }      // proc to resit (CZ)
    public string Risk { get; set; }     // "Safe" / "Moderate" / "Aggressive"
    public string Hive { get; set; }     // "HKLM" / "HKCU"
    public string Key { get; set; }
    public string Name { get; set; }
    public string Type { get; set; }     // "DWord" / "String" / "QWord" ...
    public object Value { get; set; }    // pozadovana hodnota (int nebo string)

    public static readonly Dictionary<string, int> RiskRank = new()
    {
        ["Safe"] = 1, ["Moderate"] = 2, ["Aggressive"] = 3
    };
}
