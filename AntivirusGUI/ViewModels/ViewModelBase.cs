using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace AntivirusGUI.ViewModels;

/// <summary>
/// Base ViewModel with navigation support.
/// All ViewModels inherit from ObservableObject (CommunityToolkit.Mvvm).
/// </summary>
public abstract partial class ViewModelBase : ObservableObject
{
    [ObservableProperty]
    private string _pageTitle = string.Empty;

    [ObservableProperty]
    private string _pageIcon = string.Empty;

    [ObservableProperty]
    private bool _isBusy;

    [ObservableProperty]
    private string _statusMessage = string.Empty;

    protected void SetStatus(string message)
    {
        StatusMessage = message;
    }
}
