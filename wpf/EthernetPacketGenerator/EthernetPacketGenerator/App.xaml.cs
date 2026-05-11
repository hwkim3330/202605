using System.Diagnostics;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using EthernetPacketGenerator.Services;

namespace EthernetPacketGenerator;

public partial class App : Application
{
    public LabApiServer LabServer { get; } = new(8080);

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // Keep hardware acceleration (Default) but allow the DWM to manage vsync timing
        RenderOptions.ProcessRenderMode = System.Windows.Interop.RenderMode.Default;

        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;

        EnsureFirewallRule("EthernetPacketGenerator API", 8080);

        try { LabServer.Start(); }
        catch { /* 포트 충돌 등 — 무시하고 계속 실행 */ }
    }

    // 방화벽 인바운드 규칙이 없을 때만 UAC 프롬프트를 띄워 한 번 추가한다.
    private static void EnsureFirewallRule(string ruleName, int port)
    {
        try
        {
            // 규칙 존재 여부 확인 (관리자 권한 불필요)
            var check = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName               = "netsh",
                    Arguments              = $"advfirewall firewall show rule name=\"{ruleName}\"",
                    UseShellExecute        = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow         = true
                }
            };
            check.Start();
            check.StandardOutput.ReadToEnd();
            check.WaitForExit();

            if (check.ExitCode == 0) return; // 이미 규칙 있음

            // 규칙 없음 → UAC 권한 상승으로 추가 (최초 1회)
            Process.Start(new ProcessStartInfo
            {
                FileName        = "netsh",
                Arguments       = $"advfirewall firewall add rule name=\"{ruleName}\" " +
                                  $"dir=in action=allow protocol=TCP localport={port}",
                UseShellExecute = true,
                Verb            = "runas",
                CreateNoWindow  = true
            })?.WaitForExit();
        }
        catch { /* 방화벽 추가 실패 시 무시 — 수동 허용 필요 */ }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        LabServer.Dispose();
        base.OnExit(e);
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show($"오류가 발생했습니다:\n{e.Exception.Message}\n\n{e.Exception.StackTrace}",
            "오류", MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }

    private void OnDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception ex)
            MessageBox.Show($"심각한 오류:\n{ex.Message}", "오류", MessageBoxButton.OK, MessageBoxImage.Error);
    }
}
