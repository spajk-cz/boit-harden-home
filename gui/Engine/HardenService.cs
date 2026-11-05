using Microsoft.Win32;

namespace BoitHardenHome.Engine;

public class CheckResult
{
    public Rule Rule { get; set; }
    public bool Compliant { get; set; }
    public string CurrentText { get; set; }
}

public static class HardenService
{
    public static string EditionId()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            return k?.GetValue("EditionID")?.ToString() ?? "?";
        }
        catch { return "?"; }
    }

    /// <summary>Jen cte – projde vsechna pravidla a vrati jejich stav.</summary>
    public static List<CheckResult> Audit()
    {
        var results = new List<CheckResult>();
        foreach (var r in Rules.All())
        {
            var s = RegistryEngine.GetState(r.Hive, r.Key, r.Name);
            results.Add(new CheckResult
            {
                Rule = r,
                Compliant = RegistryEngine.IsCompliant(r),
                CurrentText = s.ValueExists ? s.ValueStr : "(nenastaveno)"
            });
        }
        return results;
    }

    /// <summary>Aplikuje vybrana pravidla. Pred kazdou zmenou zazalohuje puvodni stav do run logu.</summary>
    public static RunLog Apply(IEnumerable<Rule> rules)
    {
        var log = new RunLog
        {
            Timestamp = DateTime.Now.ToString("s"),
            Machine = Environment.MachineName,
            EditionId = EditionId(),
            RestorePoint = RestorePoint.Create("BOIT Harden Home")
        };

        foreach (var r in rules)
        {
            var s = RegistryEngine.GetState(r.Hive, r.Key, r.Name);
            if (RegistryEngine.IsCompliant(r)) continue; // uz je v cili, nic nemenime

            RegistryEngine.SetValue(r.Hive, r.Key, r.Name, r.Value, r.Type);

            log.Changes.Add(new Change
            {
                Id = r.Id,
                Title = r.Title,
                Hive = r.Hive,
                Key = r.Key,
                Name = r.Name,
                Type = r.Type,
                NewValueStr = r.Value.ToString(),
                Prior = new PriorState
                {
                    KeyExists = s.KeyExists,
                    ValueExists = s.ValueExists,
                    Kind = s.Kind,
                    ValueStr = s.ValueStr
                }
            });
        }

        if (log.Changes.Count > 0) log.Save();
        return log;
    }

    /// <summary>Vrati zmeny z daneho behu presne do puvodniho stavu.</summary>
    public static int Revert(RunLog log)
    {
        int done = 0;
        // V opacnem poradi.
        for (int i = log.Changes.Count - 1; i >= 0; i--)
        {
            var c = log.Changes[i];
            try
            {
                if (c.Prior.ValueExists)
                    RegistryEngine.SetValue(c.Hive, c.Key, c.Name, c.Prior.ValueStr, c.Prior.Kind);
                else
                    RegistryEngine.RemoveValue(c.Hive, c.Key, c.Name, c.Prior.KeyExists);
                done++;
            }
            catch { /* best-effort, pokracuj dal */ }
        }
        log.Reverted = true;
        log.Resave();
        return done;
    }
}
