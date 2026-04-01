using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using AntivirusGUI.ViewModels;

namespace AntivirusGUI.Views;

public partial class CleanerView : UserControl { public CleanerView() => InitializeComponent(); }

public class FileSizeConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c)
        => value is long size ? CleanerViewModel.FormatSize(size) : "0 B";
    public object ConvertBack(object? value, Type t, object? p, CultureInfo c)
        => throw new NotSupportedException();
}

public class NonZeroToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type t, object? p, CultureInfo c)
    {
        if (value is long v) return v > 0 ? Visibility.Visible : Visibility.Collapsed;
        if (value is int i) return i > 0 ? Visibility.Visible : Visibility.Collapsed;
        if (value is string s) return !string.IsNullOrEmpty(s) ? Visibility.Visible : Visibility.Collapsed;
        return Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type t, object? p, CultureInfo c)
        => throw new NotSupportedException();
}
