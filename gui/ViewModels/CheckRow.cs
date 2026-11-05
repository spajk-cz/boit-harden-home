using System.ComponentModel;
using System.Windows;
using System.Windows.Media;
using BoitHardenHome.Engine;

namespace BoitHardenHome.ViewModels;

public class CheckRow : INotifyPropertyChanged
{
    public Rule Rule { get; }
    public bool Actionable { get; }       // true = je co napravovat
    public string CurrentText { get; }

    public CheckRow(CheckResult r)
    {
        Rule = r.Rule;
        Actionable = !r.Compliant;
        CurrentText = r.CurrentText;
        _isSelected = Actionable; // prednastaveno k aplikaci, kdyz je co menit
    }

    private bool _isSelected;
    public bool IsSelected
    {
        get => _isSelected;
        set { _isSelected = value; OnChanged(nameof(IsSelected)); }
    }

    public string Category => Rule.Cat;
    public string Title => Rule.Title;
    public string Desc => Rule.Desc;
    public string Why => Rule.Why;
    public string Risk => Rule.Risk;

    public string RiskLabel => Rule.Risk switch
    {
        "Safe" => "BEZPEČNÉ",
        "Moderate" => "STŘEDNÍ",
        "Aggressive" => "AGRESIVNÍ",
        _ => Rule.Risk.ToUpper()
    };

    public Brush RiskBrush => Rule.Risk switch
    {
        "Safe" => new SolidColorBrush(Color.FromRgb(0xD3, 0xFC, 0x23)),
        "Moderate" => new SolidColorBrush(Color.FromRgb(0xFF, 0xC2, 0x4B)),
        "Aggressive" => new SolidColorBrush(Color.FromRgb(0xFF, 0x7A, 0x45)),
        _ => Brushes.Gray
    };

    public string StatusText => Actionable ? "K NÁPRAVĚ" : "V POŘÁDKU";
    public Brush StatusBrush => Actionable
        ? new SolidColorBrush(Color.FromRgb(0xFF, 0x5A, 0x5A))
        : new SolidColorBrush(Color.FromRgb(0xD3, 0xFC, 0x23));

    public Visibility CheckVisibility => Actionable ? Visibility.Visible : Visibility.Collapsed;
    public double RowOpacity => Actionable ? 1.0 : 0.55;

    public event PropertyChangedEventHandler PropertyChanged;
    private void OnChanged(string n) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
}
