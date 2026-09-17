using System;

namespace WinWiFi;

/// <summary>Windows desktop entry point. Launching WinWiFi always opens the live scanner.</summary>
public static class Program
{
    [STAThread]
    public static int Main()
    {
        var app = new App();
        app.InitializeComponent();
        return app.Run();
    }
}
