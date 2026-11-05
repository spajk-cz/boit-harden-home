using System.IO;
using System.Text.Json;

namespace BoitHardenHome.Engine;

public class PriorState
{
    public bool KeyExists { get; set; }
    public bool ValueExists { get; set; }
    public string Kind { get; set; }
    public string ValueStr { get; set; }
}

public class Change
{
    public string Id { get; set; }
    public string Title { get; set; }
    public string Hive { get; set; }
    public string Key { get; set; }
    public string Name { get; set; }
    public string Type { get; set; }
    public string NewValueStr { get; set; }
    public PriorState Prior { get; set; }
}

public class RunLog
{
    public string App { get; set; } = "BOIT Harden Home";
    public string Timestamp { get; set; }
    public string Machine { get; set; }
    public string EditionId { get; set; }
    public bool RestorePoint { get; set; }
    public bool Reverted { get; set; }
    public List<Change> Changes { get; set; } = new();

    public string FilePath { get; set; }   // neni serializovano do obsahu, jen pro UI

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public static string DataDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "BOIT-Harden");
    public static string RunsDir => Path.Combine(DataDir, "runs");

    public static void EnsureDirs()
    {
        Directory.CreateDirectory(RunsDir);
    }

    public void Save()
    {
        EnsureDirs();
        var stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss");
        FilePath = Path.Combine(RunsDir, $"run-{stamp}.json");
        File.WriteAllText(FilePath, JsonSerializer.Serialize(this, JsonOpts));
    }

    public void Resave()
    {
        if (string.IsNullOrEmpty(FilePath)) { Save(); return; }
        File.WriteAllText(FilePath, JsonSerializer.Serialize(this, JsonOpts));
    }

    public static List<RunLog> LoadAll()
    {
        EnsureDirs();
        var list = new List<RunLog>();
        foreach (var f in Directory.GetFiles(RunsDir, "run-*.json").OrderByDescending(x => x))
        {
            try
            {
                var log = JsonSerializer.Deserialize<RunLog>(File.ReadAllText(f));
                if (log != null) { log.FilePath = f; list.Add(log); }
            }
            catch { /* preskoc poskozeny log */ }
        }
        return list;
    }
}
