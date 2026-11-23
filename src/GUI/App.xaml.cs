using System.Windows;

namespace Password_Manager.GUI;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        
        window.Show();
    }
}
