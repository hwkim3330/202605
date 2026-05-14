using System.Diagnostics;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using EthernetPacketGenerator.Services;

namespace EthernetPacketGenerator;

public partial class App : Application
{
    private const int ApiPort = 8080;

    public LabApiServer? LabServer { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        RenderOptions.ProcessRenderMode = System.Windows.Interop.RenderMode.Default;

        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;

        // 방화벽 규칙은 백그라운드에서 처리 (UI 블로킹 방지)
        Task.Run(() => EnsureFirewallRule("EthernetPacketGenerator API", ApiPort));

        LabServer = new LabApiServer(ApiPort);
        try
        {
            LabServer.Start();
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"포트 {ApiPort}을 바인드할 수 없습니다:\n{ex.Message}\n\n다른 프로그램이 이미 해당 포트를 사용 중일 수 있습니다.",
                "서버 시작 오류",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            LabServer.Dispose();
            LabServer = null;
        }

        MainWindow mainWindow;
        try
        {
            mainWindow = new MainWindow();
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"앱 초기화 오류:\n{ex.Message}\n\n{ex.StackTrace}",
                "시작 오류",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            Shutdown(1);
            return;
        }

        MainWindow = mainWindow;
        mainWindow.Show();

        if (LabServer != null && mainWindow.DataContext is ViewModels.MainViewModel vm)
        {
            LabServer.MainVm = vm;
            LabServer.AutomationVm = vm.AutomationVM;
            LabServer.CaptureVm = vm.CaptureVM;
            LabServer.HyperTerminalVm = vm.HyperTerminalVM;
        }
    }

    private static void EnsureFirewallRule(string ruleName, int port)
    {
        try
        {
            var check = new ProcessStartInfo("netsh",
                $"advfirewall firewall show rule name=\"{ruleName}\"")
            { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true };
            using var p = Process.Start(check);
            p?.WaitForExit(3000);
            if (p?.ExitCode == 0) return;

            var add = new ProcessStartInfo("netsh",
                $"advfirewall firewall add rule name=\"{ruleName}\" protocol=TCP dir=in localport={port} action=allow")
            { CreateNoWindow = true, UseShellExecute = true, Verb = "runas" };
            using var p2 = Process.Start(add);
            p2?.WaitForExit(5000);
        }
        catch { }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        LabServer?.Dispose();
        base.OnExit(e);
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show(
            $"Unhandled error:\n{e.Exception.Message}\n\n{e.Exception.StackTrace}",
            "Error",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
        e.Handled = true;
    }

    private void OnDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception ex)
            MessageBox.Show($"Fatal error:\n{ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}
