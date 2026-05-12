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

                // 헤더 + 바디 읽기. TCP 분절로 헤더와 바디가 따로 올 수 있으므로
                // Content-Length만큼 모두 수신한 뒤 파싱한다.
                var buf   = new byte[65536];
                int n     = await stream.ReadAsync(buf).ConfigureAwait(false);
                int bodyDelim = -1;

                // 헤더 끝(\r\n\r\n) 탐색 — 미발견 시 추가 읽기
                while (n < buf.Length)
                {
                    var headerScan = Encoding.ASCII.GetString(buf, 0, n);
                    bodyDelim = headerScan.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                    if (bodyDelim >= 0)
                    {
                        // Content-Length 파싱 후 바디 완전 수신
                        var headers = headerScan[..bodyDelim];
                        var clm = System.Text.RegularExpressions.Regex.Match(
                            headers, @"Content-Length:\s*(\d+)",
                            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                        if (clm.Success)
                        {
                            int contentLen = int.Parse(clm.Groups[1].Value);
                            int bodyRecv   = n - (bodyDelim + 4);
                            while (bodyRecv < contentLen && n < buf.Length)
                            {
                                int r = await stream.ReadAsync(buf, n, buf.Length - n).ConfigureAwait(false);
                                if (r == 0) break;
                                n       += r;
                                bodyRecv += r;
                            }
                        }
                        break;
                    }
                    // 헤더 끝 아직 미도착 — 추가 읽기
                    int more = await stream.ReadAsync(buf, n, buf.Length - n).ConfigureAwait(false);
                    if (more == 0) break;
                    n += more;
                }

                if (bodyDelim < 0)
                {
                    var scan = Encoding.ASCII.GetString(buf, 0, n);
                    bodyDelim = scan.IndexOf("\r\n\r\n", StringComparison.Ordinal);
                }

                var raw  = Encoding.UTF8.GetString(buf, 0, n);
                var requestLine = raw.Split('\n')[0].Trim();
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
                    // activeInterfaces: IsActive 체크된 항목의 OS 인터페이스 이름 (MAC 매칭)
                    var activeNames = new JsonArray();
                    foreach (var e in ActiveInterfaceEntries.Where(e => e.IsActive))
                    {
                        var osName = GetOsInterfaceName(e.Device) ?? e.ShortName;
                        activeNames.Add(JsonValue.Create(osName));
                    }

                    // selectedInterface: Default 디바이스의 OS 이름 (probe 드롭다운 자동선택용)
                    var defaultOsName = GetOsInterfaceName(ActiveDevice) ?? SelectedInterfaceName;

                    var payload = new JsonObject
                    {
                        ["ok"]                = true,
                        ["interfaces"]        = BuildInterfaceList(),
                        ["selectedInterface"] = defaultOsName,
                        ["defaultInterface"]  = defaultOsName,
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
                else if (requestLine.StartsWith("POST /api/validate", StringComparison.OrdinalIgnoreCase))
                {
                    (responseBody, status) = await HandleValidateAsync(body).ConfigureAwait(false);
                }
                else if (requestLine.StartsWith("POST /api/capture", StringComparison.OrdinalIgnoreCase))
                {
                    (responseBody, status) = await HandleCaptureAsync(body).ConfigureAwait(false);
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

            // profile["interface"]에 OS 인터페이스 이름이 있으면 해당 디바이스를 우선 사용,
            // 없거나 매칭 실패 시 ActiveDevice(Default) 사용
            var ifaceName = profile["interface"]?.GetValue<string>();
            var dev = (ifaceName != null ? ResolveDevice(ifaceName) : null)
                      ?? ActiveDevice
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

    // ── POST /api/validate ────────────────────────────────────────────────────
    // {txInterface?, rxInterface?, count?, timeoutMs?, interPacketMs?, matchMode?, rxFilter?, ...packet profile}

    private async Task<(string body, int status)> HandleValidateAsync(string jsonBody)
    {
        try
        {
            var req = JsonNode.Parse(jsonBody) as JsonObject
                      ?? throw new ArgumentException("invalid JSON");

            var txName = req["txInterface"]?.GetValue<string>();
            var rxName = req["rxInterface"]?.GetValue<string>() ?? txName;

            var txDev = (txName != null ? ResolveDevice(txName) : null)
                        ?? ActiveDevice
                        ?? throw new InvalidOperationException("TX 인터페이스를 찾을 수 없습니다.");
            var rxDev = (rxName != null ? ResolveDevice(rxName) : null)
                        ?? ActiveDevice
                        ?? throw new InvalidOperationException("RX 인터페이스를 찾을 수 없습니다.");

            var count         = req["count"]?.GetValue<int>()        ?? 1;
            var timeoutMs     = req["timeoutMs"]?.GetValue<int>()     ?? 2000;
            var interPacketMs = req["interPacketMs"]?.GetValue<int>() ?? 10;
            var rxFilter      = req["rxFilter"]?.GetValue<string>()   ?? string.Empty;
            var matchModeStr  = req["matchMode"]?.GetValue<string>()  ?? "exact";

            var matchMode = matchModeStr.ToLowerInvariant() switch
            {
                "payload"          => EthernetPacketGenerator.Models.ValidationMatchMode.Payload,
                "dstmacandpayload" => EthernetPacketGenerator.Models.ValidationMatchMode.DstMacAndPayload,
                _                  => EthernetPacketGenerator.Models.ValidationMatchMode.Exact
            };

            var (frame, _) = LabPacketService.BuildFrame(req);

            var config = new EthernetPacketGenerator.Models.ValidationConfig
            {
                Count         = count,
                TimeoutMs     = timeoutMs,
                InterPacketMs = interPacketMs,
                MatchMode     = matchMode,
                RxFilter      = rxFilter
            };

            var svc = new PacketValidationService();
            var (summary, records) = await svc.RunAsync(txDev, rxDev, new[] { frame }, config)
                                              .ConfigureAwait(false);

            var recArr = new JsonArray();
            foreach (var r in records)
                recArr.Add(new JsonObject
                {
                    ["index"]     = r.Index,
                    ["status"]    = r.Status.ToString().ToLower(),
                    ["sentLen"]   = r.SentLength,
                    ["recvLen"]   = r.ReceivedLength,
                    ["latencyMs"] = r.LatencyMs,
                    ["note"]      = r.Note
                });

            var result = new JsonObject
            {
                ["ok"]     = true,
                ["stdout"] = new JsonObject
                {
                    ["txCount"]       = summary.TxCount,
                    ["rxCount"]       = summary.RxCount,
                    ["matchCount"]    = summary.MatchCount,
                    ["mismatchCount"] = summary.MismatchCount,
                    ["lostCount"]     = summary.LostCount,
                    ["lossRate"]      = Math.Round(summary.LossRate,  2),
                    ["matchRate"]     = Math.Round(summary.MatchRate, 2),
                    ["elapsedMs"]     = Math.Round(summary.ElapsedMs, 1),
                    ["avgLatencyMs"]  = Math.Round(summary.AvgLatencyMs, 3),
                    ["records"]       = recArr
                }
            };
            return (result.ToJsonString(), 200);
        }
        catch (Exception ex)
        {
            return ($"{{\"ok\":false,\"error\":{System.Text.Json.JsonSerializer.Serialize(ex.Message)}}}", 400);
        }
    }

    // ── POST /api/capture ─────────────────────────────────────────────────────
    // {interface?, filter?, count, timeoutMs?}

    private async Task<(string body, int status)> HandleCaptureAsync(string jsonBody)
    {
        try
        {
            var req = JsonNode.Parse(jsonBody) as JsonObject
                      ?? throw new ArgumentException("invalid JSON");

            var ifName    = req["interface"]?.GetValue<string>();
            var filter    = req["filter"]?.GetValue<string>()    ?? string.Empty;
            var count     = Math.Clamp(req["count"]?.GetValue<int>()     ?? 10, 1, 1000);
            var timeoutMs = req["timeoutMs"]?.GetValue<int>()             ?? 5000;

            var dev = (ifName != null ? ResolveDevice(ifName) : null)
                      ?? ActiveDevice
                      ?? throw new InvalidOperationException("인터페이스가 선택되지 않았습니다.");

            var packets = new System.Collections.Concurrent.ConcurrentQueue<JsonObject>();
            using var cts    = new CancellationTokenSource(timeoutMs);
            using var signal = new SemaphoreSlim(0, count + 1);
            int seq = 0;

            void OnArrival(object _, PacketCapture e)
            {
                try
                {
                    var raw  = e.GetPacket();
                    var data = raw.Data.ToArray();
                    int s    = System.Threading.Interlocked.Increment(ref seq);
                    packets.Enqueue(new JsonObject
                    {
                        ["seq"]         = s,
                        ["timestampNs"] = LabPacketService.HighResNs(),
                        ["length"]      = data.Length,
                        ["hex"]         = Convert.ToHexString(data).ToLower()
                    });
                    signal.Release();
                    if (s >= count) cts.Cancel();
                }
                catch { }
            }

            try
            {
                dev.Open(DeviceModes.None, timeoutMs);
                if (!string.IsNullOrWhiteSpace(filter))
                    try { dev.Filter = filter; } catch { }
                dev.OnPacketArrival += OnArrival;
                dev.StartCapture();

                for (int i = 0; i < count && !cts.Token.IsCancellationRequested; i++)
                {
                    try { await signal.WaitAsync(cts.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { break; }
                }
            }
            finally
            {
                dev.OnPacketArrival -= OnArrival;
                try { dev.StopCapture(); dev.Close(); } catch { }
            }

            var pktArr = new JsonArray();
            while (packets.TryDequeue(out var p)) pktArr.Add(p);

            var result = new JsonObject
            {
                ["ok"]     = true,
                ["stdout"] = new JsonObject
                {
                    ["captured"] = pktArr.Count,
                    ["packets"]  = pktArr
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

    // ── SharpPcap 디바이스 → OS 인터페이스 이름 ──────────────────────────────

    /// <summary>MAC 매칭으로 SharpPcap 디바이스에 해당하는 OS NIC 이름을 반환한다.</summary>
    private static string? GetOsInterfaceName(ILiveDevice? dev)
    {
        if (dev == null) return null;
        try
        {
            var macBytes = dev.MacAddress?.GetAddressBytes();
            if (macBytes?.Length != 6) return null;
            return NetworkInterface.GetAllNetworkInterfaces()
                .FirstOrDefault(n =>
                {
                    var b = n.GetPhysicalAddress().GetAddressBytes();
                    return b.Length == 6 && b.SequenceEqual(macBytes);
                })?.Name;
        }
        catch { return null; }
    }

    // ── 인터페이스 이름 → SharpPcap 디바이스 해석 ────────────────────────────

    /// <summary>
    /// OS 인터페이스 이름(예: "Ethernet 2")으로 MAC을 찾고,
    /// ActiveInterfaceEntries에서 동일 MAC인 SharpPcap 디바이스를 반환한다.
    /// 없거나 열리지 않은 경우 열기를 시도하고 반환; 실패 시 null.
    /// </summary>
    private ILiveDevice? ResolveDevice(string osIfaceName)
    {
        if (string.IsNullOrWhiteSpace(osIfaceName)) return null;

        // OS NIC 이름 → MAC
        var nic = NetworkInterface.GetAllNetworkInterfaces()
            .FirstOrDefault(n => n.Name.Equals(osIfaceName, StringComparison.OrdinalIgnoreCase));
        if (nic == null) return null;

        var macBytes = nic.GetPhysicalAddress().GetAddressBytes();
        if (macBytes.Length != 6) return null;

        // 1차: ActiveInterfaceEntries에서 MAC 매칭
        var entry = ActiveInterfaceEntries.FirstOrDefault(e =>
        {
            try
            {
                var devMac = e.Device?.MacAddress?.GetAddressBytes();
                return devMac?.Length == 6 && devMac.SequenceEqual(macBytes);
            }
            catch { return false; }
        });

        if (entry?.Device != null)
        {
            try { entry.Device.Open(DeviceModes.None); } catch { }
            return entry.Device;
        }

        // 2차 폴백: 등록되지 않은(IsActive=false 등) 인터페이스도 포함해 전체 SharpPcap 디바이스 검색
        try
        {
            foreach (var dev in SharpPcap.CaptureDeviceList.Instance)
            {
                try
                {
                    var devMac = dev.MacAddress?.GetAddressBytes();
                    if (devMac?.Length == 6 && devMac.SequenceEqual(macBytes))
                    {
                        dev.Open(DeviceModes.None);
                        return dev;
                    }
                }
                catch { }
            }
        }
        catch { }

        return null;
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
