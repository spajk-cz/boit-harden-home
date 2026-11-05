using Microsoft.Win32;

namespace BoitHardenHome.Engine;

public class RegState
{
    public bool KeyExists { get; set; }
    public bool ValueExists { get; set; }
    public string Kind { get; set; }       // napr. "DWord"
    public string ValueStr { get; set; }   // hodnota serializovana do stringu
}

public static class RegistryEngine
{
    private static RegistryKey BaseKey(string hive) =>
        hive == "HKLM" ? Registry.LocalMachine : Registry.CurrentUser;

    public static RegState GetState(string hive, string key, string name)
    {
        var rs = new RegState();
        using var sub = BaseKey(hive).OpenSubKey(key, false);
        if (sub != null)
        {
            rs.KeyExists = true;
            var names = sub.GetValueNames();
            if (names.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                var kind = sub.GetValueKind(name);
                rs.ValueExists = true;
                rs.Kind = kind.ToString();
                rs.ValueStr = ToStr(sub.GetValue(name), kind);
            }
        }
        return rs;
    }

    public static void SetValue(string hive, string key, string name, object value, string type)
    {
        using var sub = BaseKey(hive).CreateSubKey(key, true);
        if (sub == null) throw new InvalidOperationException($"Nelze otevřít/vytvořit klíč {hive}\\{key}");
        var kind = Enum.Parse<RegistryValueKind>(type);
        sub.SetValue(name, Coerce(value, kind), kind);
    }

    public static void RemoveValue(string hive, string key, string name, bool keyExistedBefore)
    {
        var baseKey = BaseKey(hive);
        using (var sub = baseKey.OpenSubKey(key, true))
        {
            if (sub == null) return;
            if (sub.GetValueNames().Contains(name, StringComparer.OrdinalIgnoreCase))
                sub.DeleteValue(name, false);

            // Pokud klic predtim neexistoval a je ted prazdny, uklidime ho.
            if (!keyExistedBefore && sub.ValueCount == 0 && sub.SubKeyCount == 0)
            {
                // sub musime zavrit pred smazanim klice
            }
            else
            {
                return;
            }
        }
        if (!keyExistedBefore)
        {
            try { baseKey.DeleteSubKey(key, false); } catch { /* best-effort */ }
        }
    }

    public static bool IsCompliant(Rule r)
    {
        var s = GetState(r.Hive, r.Key, r.Name);
        if (!s.ValueExists) return false;
        if (r.Type == "DWord") return s.ValueStr == Convert.ToInt32(r.Value).ToString();
        if (r.Type == "QWord") return s.ValueStr == Convert.ToInt64(r.Value).ToString();
        return s.ValueStr == r.Value.ToString();
    }

    private static string ToStr(object val, RegistryValueKind kind)
    {
        if (val == null) return null;
        if (kind == RegistryValueKind.MultiString && val is string[] arr) return string.Join("\n", arr);
        return val.ToString();
    }

    private static object Coerce(object value, RegistryValueKind kind)
    {
        switch (kind)
        {
            case RegistryValueKind.DWord: return Convert.ToInt32(value);
            case RegistryValueKind.QWord: return Convert.ToInt64(value);
            case RegistryValueKind.MultiString:
                return value is string[] a ? a : value.ToString().Split('\n');
            default: return value.ToString();
        }
    }
}
