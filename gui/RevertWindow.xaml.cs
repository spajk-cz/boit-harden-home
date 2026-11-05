using System.Collections.Generic;
using System.Linq;
using System.Windows;
using BoitHardenHome.Engine;

namespace BoitHardenHome;

public partial class RevertWindow : Window
{
    private class RunItem
    {
        public RunLog Log { get; set; }
        public string Header { get; set; }
        public string Sub { get; set; }
    }

    public RevertWindow()
    {
        InitializeComponent();
        LoadRuns();
    }

    private void LoadRuns()
    {
        var items = new List<RunItem>();
        foreach (var log in RunLog.LoadAll())
        {
            var state = log.Reverted ? "  ·  již vráceno" : "";
            items.Add(new RunItem
            {
                Log = log,
                Header = $"{log.Timestamp}  ·  {log.Changes.Count} změn{state}",
                Sub = $"{log.Machine}  ·  edice {log.EditionId}  ·  {System.IO.Path.GetFileName(log.FilePath)}"
            });
        }
        RunsList.ItemsSource = items;
        if (items.Count > 0) RunsList.SelectedIndex = 0;
    }

    private void Revert_Click(object sender, RoutedEventArgs e)
    {
        if (RunsList.SelectedItem is not RunItem item)
        {
            MessageBox.Show("Vyberte běh k vrácení.", "Vrátit změny", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var res = MessageBox.Show(
            $"Vrátit {item.Log.Changes.Count} změn z běhu {item.Log.Timestamp} zpět do původního stavu?",
            "Potvrzení", MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (res != MessageBoxResult.Yes) return;

        try
        {
            int done = HardenService.Revert(item.Log);
            MessageBox.Show(
                $"Vráceno {done} změn.\nNěkteré změny (např. služby) se projeví po restartu.",
                "Hotovo", MessageBoxButton.OK, MessageBoxImage.Information);
            LoadRuns();
        }
        catch (System.Exception ex)
        {
            MessageBox.Show("Chyba při vracení:\n" + ex.Message, "Chyba", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
