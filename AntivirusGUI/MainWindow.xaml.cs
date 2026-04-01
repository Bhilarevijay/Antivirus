using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using AntivirusGUI.ViewModels;

namespace AntivirusGUI;

public partial class MainWindow : Window
{
    private bool _isLoaded;

    public MainWindow()
    {
        InitializeComponent();
        Loaded += (s, e) =>
        {
            _isLoaded = true;
            if (DataContext is MainViewModel vm)
            {
                vm.PropertyChanged += (_, args) =>
                {
                    if (args.PropertyName == nameof(MainViewModel.CurrentViewModel))
                        PlayPageAnimation();
                };
            }
        };
    }

    private void PlayPageAnimation()
    {
        if (!_isLoaded) return;
        try
        {
            // Fade-in + slide-up animation via code
            var fadeAnim = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(250))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };
            var slideAnim = new DoubleAnimation(20, 0, TimeSpan.FromMilliseconds(300))
            {
                EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
            };

            PageContainer.BeginAnimation(OpacityProperty, fadeAnim);
            PageTranslate.BeginAnimation(TranslateTransform.YProperty, slideAnim);
        }
        catch { /* Animation failure should never crash */ }
    }

    private void TitleBar_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.ClickCount == 2)
            ToggleMaximize();
        else
            DragMove();
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) =>
        WindowState = WindowState.Minimized;

    private void Maximize_Click(object sender, RoutedEventArgs e) =>
        ToggleMaximize();

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        // Shut down the entire application (triggers App.OnExit which kills child processes)
        Application.Current.Shutdown();
    }

    private void ToggleMaximize() =>
        WindowState = WindowState == WindowState.Maximized
            ? WindowState.Normal : WindowState.Maximized;
}