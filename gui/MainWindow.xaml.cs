using System.Collections.ObjectModel;
using System.Linq;
using System.Windows;
using BoitHardenHome.Engine;
using BoitHardenHome.ViewModels;

namespace BoitHardenHome;

public partial class MainWindow : Window
{
    private readonly ObservableCollection<CheckRow> _rows = new();

    public MainWindow()
    {
        InitializeComponent();
        List.ItemsSource = _rows;
        Loaded += (_, _) => Scan();
    }

    private int SelectedTierRank => TierCombo.SelectedIndex switch
    {
        0 => 1, // Safe
        1 => 2, // Moderate
        2 => 3, // Aggressive
        _ => 1
    };

    private void Scan()
    {
        _rows.Clear();
        var audit = HardenService.Audit();
        foreach (var r in audit.OrderBy(a => a.Rule.Cat).ThenBy(a => a.Rule.Id))
            _rows.Add(new CheckRow(r));

        ApplyTierSelection();
        UpdateStats();
        StatusBar.Text = $"Zkontrolováno {audit.Count} nastavení · stanice {Environment.MachineName} · edice {HardenService.EditionId()}";
    }

    private void ApplyTierSelection()
    {
        int rank = SelectedTierRank;
        foreach (var row in _rows)
            row.IsSelected = row.Actionable && Rule.RiskRank[row.Risk] <= rank;
    }

    private void UpdateStats()
    {
        int ok = _rows.Count(r => !r.Actionable);
        int fix = _rows.Count(r => r.Actionable);
        OkCount.Text = ok.ToString();
        FixCount.Text = fix.ToString();
    }

    private void TierCombo_Changed(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (_rows.Count > 0) ApplyTierSelection();
    }

    private void SelectAll_Click(object sender, RoutedEventArgs e)
    {
        foreach (var row in _rows.Where(r => r.Actionable)) row.IsSelected = true;
    }

    private void SelectNone_Click(object sender, RoutedEventArgs e)
    {
        foreach (var row in _rows) row.IsSelected = false;
    }

    private void Apply_Click(object sender, RoutedEventArgs e)
    {
        var chosen = _rows.Where(r => r.Actionable && r.IsSelected).Select(r => r.Rule).ToList();
        if (chosen.Count == 0)
        {
            MessageBox.Show("Nevybrali jste žádnou změnu.", "BOIT Harden Home",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var agg = chosen.Count(r => r.Risk == "Aggressive");
        var warn = agg > 0 ? $"\n\nPozor: {agg} z nich je označeno jako agresivní – mohou ovlivnit některé aplikace." : "";
        var res = MessageBox.Show(
            $"Chystáte se použít {chosen.Count} změn.{warn}\n\nPřed změnami se vytvoří bod obnovení systému a vše půjde kdykoli vrátit zpět.\n\nPokračovat?",
            "Potvrzení", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (res != MessageBoxResult.Yes) return;

        try
        {
            ApplyBtn.IsEnabled = false;
            StatusBar.Text = "Aplikuji změny…";
            var log = HardenService.Apply(chosen);

            var rp = log.RestorePoint ? "Bod obnovení byl vytvořen." : "Bod obnovení se nepodařilo vytvořit (revert ale funguje).";
            MessageBox.Show(
                $"Hotovo. Změněno: {log.Changes.Count}.\n{rp}\n\nNěkteré změny (např. služby) se projeví po restartu.",
                "Dokončeno", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show("Při aplikaci došlo k chybě:\n" + ex.Message, "Chyba",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            ApplyBtn.IsEnabled = true;
            Scan();
        }
    }

    private void Revert_Click(object sender, RoutedEventArgs e)
    {
        var win = new RevertWindow { Owner = this };
        win.ShowDialog();
        Scan();
    }
}
