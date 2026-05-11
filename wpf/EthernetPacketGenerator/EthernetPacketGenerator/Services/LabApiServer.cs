using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json.Nodes;
using SharpPcap;

namespace EthernetPacketGenerator.Services;

/// <summary>
/// TcpListener 기반 경량 HTTP 서버 (관리자 권한 불필요).
/// GET  /api/interfaces  — NIC 목록 + 선택 인터페이스
/// POST /api/build       — 프레임 빌드 (frameHex + decoded)
/// POST /api/send        — 프레임 전송
/// 기본 포트: 8080
/// </summary>
public sealed class LabApiServer : IDisposable
{
    private readonly TcpListener _listener;
    private CancellationTokenSource? _cts;
    private bool _disposed;

    public int Port { get; }
    public bool IsRunning { get; private set; }

    /// <summary>SendViewModel이 갱신 — /api/interfaces 응답에 포함 (Default 인터페이스 이름)</summary>
    public string? SelectedInterfaceName { get; set; }

    /// <summary>SendViewModel이 갱신 — /api/send 시 실제 전송에 사용 (Default 디바이스)</summary>
    public ILiveDevice? ActiveDevice { get; set; }

    /// <summary>SendViewModel이 갱신 — /api/interfaces 응답의 activeInterfaces 목록에 사용</summary>
    public List<EthernetPacketGenerator.Models.InterfaceEntry> ActiveInterfaceEntries { get; set; } = new();

    public LabApiServer(int port = 8080)
    {
        Port = port;
        _listener = new TcpListener(IPAddress.Any, port);
    }

    public void Start()
    {
        _listener.Start();
        IsRunning = true;
        _cts = new CancellationTokenSource();
        Task.Run(() => AcceptLoop(_cts.Token));
    }

    public void Stop()
    {
        _cts?.Cancel();
        try { _listener.Stop(); } catch { }
    }

    // ── Accept loop ───────────────────────────────────────────────────────────

    private async Task AcceptLoop(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            TcpClient client;
            try { client = await _listener.AcceptTcpClientAsync(token); }
            catch { break; }
            _ = Task.Run(() => HandleAsync(client), token);
        }
    }

    // ── Request handler ───────────────────────────────────────────────────────

    private async Task HandleAsync(TcpClient client)
    {
        using (client)
        {
            try
            {
                using var stream = client.GetStream();

                // 최대 64 KB 읽기 (헤더 + JSON 바디)
                var buf = new byte[65536];
                var n   = await stream.ReadAsync(buf).ConfigureAwait(false);
                var raw = Encoding.UTF8.GetString(buf, 0, n);

                var requestLine = raw.Split('\n')[0].Trim();
                var bodyDelim   = raw.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                var body        = bodyDelim >= 0 ? raw[(bodyDelim + 4)..].TrimEnd('\0') : string.Empty;

                string responseBody;
                int    status;

                // CORS preflight
                if (requestLine.StartsWith("OPTIONS", StringComparison.OrdinalIgnoreCase))
                {
                    var pre = "HTTP/1.1 204 No Content\r\n" +
                              "Access-Control-Allow-Origin: *\r\n" +
                              "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n" +
                              "Access-Control-Allow-Headers: Content-Type\r\n" +
                              "Content-Length: 0\r\n\r\n";
                    await stream.WriteAsync(Encoding.ASCII.GetBytes(pre)).ConfigureAwait(false);
                    return;
                }

                if (requestLine.StartsWith("GET /api/interfaces", StringComparison.OrdinalIgnoreCase))
                {
                    var activeNames = new JsonArray();
                    foreach (var e in ActiveInterfaceEntries.Where(e => e.IsActive))
                        activeNames.Add(JsonValue.Create(e.ShortName));

                    var payload = new JsonObject
                    {
                        ["ok"]                = true,
                        ["interfaces"]        = BuildInterfaceList(),
                        ["selectedInterface"] = SelectedInterfaceName,   // 하위 호환
                        ["defaultInterface"]  = SelectedInterfaceName,
                        ["activeInterfaces"]  = activeNames
                    };
                    responseBody = payload.ToJsonString();
                    status       = 200;
                }
                else if (requestLine.StartsWith("POST /api/build", StringComparison.OrdinalIgnoreCase))
                {
                    (responseBody, status) = HandleBuild(body);
                }
                else if (requestLine.StartsWith("POST /api/send", StringComparison.OrdinalIgnoreCase))
                {
                    (responseBody, status) = await HandleSendAsync(body).ConfigureAwait(false);
                }
                else
                {
                    responseBody = "{\"ok\":false,\"error\":\"not found\"}";
                    status       = 404;
                }

                var bodyBytes   = Encoding.UTF8.GetBytes(responseBody);
                var statusText  = status == 200 ? "OK" : status == 400 ? "Bad Request" : "Not Found";
                var headerBytes = Encoding.ASCII.GetBytes(
                    $"HTTP/1.1 {status} {statusText}\r\n" +
                    $"Content-Type: application/json; charset=utf-8\r\n" +
                    $"Content-Length: {bodyBytes.Length}\r\n" +
                    $"Access-Control-Allow-Origin: *\r\n" +
                    $"Connection: close\r\n\r\n");

                await stream.WriteAsync(headerBytes).ConfigureAwait(false);
                await stream.WriteAsync(bodyBytes).ConfigureAwait(false);
            }
            catch { /* 연결 끊김 등 무시 */ }
        }
    }

    // ── POST /api/build ───────────────────────────────────────────────────────

    private static (string body, int status) HandleBuild(string jsonBody)
    {
        try
        {
            var profile = JsonNode.Parse(jsonBody) as JsonObject
                          ?? throw new ArgumentException("invalid JSON");
            var (frame, decoded) = LabPacketService.BuildFrame(profile);
            var result = new JsonObject
            {
                ["ok"]     = true,
                ["stdout"] = new JsonObject
                {
                    ["frameHex"] = Convert.ToHexString(frame).ToLower(),
                    ["decoded"]  = decoded
                }
            };
            return (result.ToJsonString(), 200);
        }
        catch (Exception ex)
        {
            return ($"{{\"ok\":false,\"error\":{System.Text.Json.JsonSerializer.Serialize(ex.Message)}}}", 400);
        }
    }

    // ── POST /api/send ────────────────────────────────────────────────────────

    private async Task<(string body, int status)> HandleSendAsync(string jsonBody)
    {
        try
        {
            var profile = JsonNode.Parse(jsonBody) as JsonObject
                          ?? throw new ArgumentException("invalid JSON");

            var dev = ActiveDevice
                      ?? throw new InvalidOperationException("No interface selected in the app");

            var count      = profile["count"]?.GetValue<int>()    ?? 1;
            var intervalMs = profile["intervalMs"]?.GetValue<double>() ?? 0;
            var recordTs   = profile["recordTimestamps"]?.GetValue<bool>() ?? false;
            var payloadObj = profile["payload"] as JsonObject;
            var isBench    = payloadObj?["mode"]?.GetValue<string>() == "benchmark";
            var seqStart   = payloadObj?["start"]?.GetValue<int>() ?? 1;

            var txRecords  = new JsonArray();
            JsonObject? lastDecoded = null;
            long bytesSent = 0;

            var sw    = Stopwatch.StartNew();
            var swRef = Stopwatch.GetTimestamp();

            for (int i = 0; i < count; i++)
            {
                var (frame, decoded) = LabPacketService.BuildFrame(profile, seqStart + i);
                lastDecoded = decoded;

                long txNs = LabPacketService.HighResNs();

                dev.SendPacket(frame);
                bytesSent += frame.Length;

                if (recordTs || isBench)
                {
                    txRecords.Add(new JsonObject
                    {
                        ["seq"]            = seqStart + i,
                        ["txTimestampNs"]  = txNs,
                        ["length"]         = frame.Length
                    });
                }

                if (intervalMs > 0 && i < count - 1)
                    await PreciseDelayAsync(intervalMs).ConfigureAwait(false);
            }

            sw.Stop();

            var result = new JsonObject
            {
                ["ok"]     = true,
                ["stdout"] = new JsonObject
                {
                    ["framesSent"]      = count,
                    ["bytesSent"]       = bytesSent,
                    ["elapsedSec"]      = sw.Elapsed.TotalSeconds,
                    ["decoded"]         = lastDecoded,
                    ["txRecords"]       = txRecords
                }
            };
            return (result.ToJsonString(), 200);
        }
        catch (Exception ex)
        {
            return ($"{{\"ok\":false,\"error\":{System.Text.Json.JsonSerializer.Serialize(ex.Message)}}}", 400);
        }
    }

    // ── Delay helper (짧은 인터벌은 SpinWait, 긴 것은 Task.Delay) ─────────────

    private static Task PreciseDelayAsync(double ms)
    {
        if (ms >= 15)
            return Task.Delay((int)ms);

        // 15ms 미만: SpinWait 기반 정밀 대기
        var target = (long)(ms * Stopwatch.Frequency / 1000.0);
        var start  = Stopwatch.GetTimestamp();
        return Task.Run(() =>
        {
            while (Stopwatch.GetTimestamp() - start < target)
                Thread.SpinWait(50);
        });
    }

    // ── /api/interfaces 헬퍼 ─────────────────────────────────────────────────

    private static JsonArray BuildInterfaceList()
    {
        var arr = new JsonArray();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
            var macBytes = nic.GetPhysicalAddress().GetAddressBytes();
            if (macBytes.Length != 6) continue;

            var mac   = string.Join(":", macBytes.Select(b => b.ToString("x2")));
            var state = nic.OperationalStatus == OperationalStatus.Up ? "up" : "down";

            int mtu = 1500;
            try { mtu = nic.GetIPProperties().GetIPv4Properties()?.Mtu ?? 1500; } catch { }

            var ipv4 = new JsonArray();
            foreach (var ua in nic.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                ipv4.Add(new JsonObject { ["local"] = ua.Address.ToString(), ["prefixlen"] = ua.PrefixLength });
            }

            arr.Add(new JsonObject
            {
                ["name"]  = nic.Name,
                ["mac"]   = mac,
                ["state"] = state,
                ["mtu"]   = mtu,
                ["ipv4"]  = ipv4
            });
        }
        return arr;
    }

    public void Dispose()
    {
        if (_disposed) return;
        Stop();
        _disposed = true;
    }
}
