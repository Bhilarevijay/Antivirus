using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;

namespace AntivirusGUI.Views;

public partial class ScanView : UserControl
{
    public ScanView() => InitializeComponent();
}

public class ZeroToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c)
        => (value is int count && count == 0) ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object? value, Type t, object? p, CultureInfo c)
        => throw new NotSupportedException();
}
