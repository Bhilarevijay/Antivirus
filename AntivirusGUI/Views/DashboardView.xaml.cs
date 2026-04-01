using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace AntivirusGUI.Views;

public partial class DashboardView : UserControl
{
    public DashboardView() => InitializeComponent();
}

/// <summary>Converts health percentage to a pixel width for progress bar</summary>
public class HealthToWidthConverter : IValueConverter
{
    public static readonly HealthToWidthConverter Instance = new();

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is double health)
            return health / 100.0 * 700; // Max width
        return 0.0;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
