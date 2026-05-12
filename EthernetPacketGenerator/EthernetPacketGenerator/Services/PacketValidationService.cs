using System.Collections.Concurrent;
using System.Diagnostics;
using EthernetPacketGenerator.Models;
using SharpPcap;

namespace EthernetPacketGenerator.Services;

/// <summary>
/// TX 인터페이스로 패킷을 전송하고 RX 인터페이스에서 수신을 검증한다.
/// TX == RX 가능 (루프백/허브), TX != RX 가능 (두-NIC 직결).
/// </summary>
public class PacketValidationService
{
    public async Task<(ValidationSummary Summary, List<PacketValidationRecord> Records)> RunAsync(
        ILiveDevice txDevice,
        ILiveDevice rxDevice,
        IReadOnlyList<byte[]> frames,
        ValidationConfig config,
        IProgress<PacketValidationRecord>? progress = null,
        CancellationToken ct = default)
    {
        if (frames.Count == 0)
            return (new ValidationSummary(), new List<PacketValidationRecord>());

        bool sameDevice = ReferenceEquals(txDevice, rxDevice);

        var rxQueue  = new ConcurrentQueue<(byte[] data, long ticks)>();
        var rxSignal = new SemaphoreSlim(0, int.MaxValue);

        void OnArrival(object _, PacketCapture e)
        {
            try
            {
                var raw = e.GetPacket();
                rxQueue.Enqueue((raw.Data.ToArray(), Stopwatch.GetTimestamp()));
                rxSignal.Release();
            }
            catch { }
        }

        // ── 디바이스 열기 ──────────────────────────────────────────────────────
        try
        {
            if (sameDevice)
                txDevice.Open(DeviceModes.None, config.TimeoutMs);
            else
            {
                txDevice.Open(DeviceModes.None);
                rxDevice.Open(DeviceModes.None, config.TimeoutMs);
            }
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"인터페이스를 열 수 없습니다 — Live Capture가 실행 중이면 먼저 중지하세요.\n{ex.Message}");
        }

        if (!string.IsNullOrWhiteSpace(config.RxFilter))
            try { rxDevice.Filter = config.RxFilter; } catch { }

        rxDevice.OnPacketArrival += OnArrival;
        rxDevice.StartCapture();

        var records     = new List<PacketValidationRecord>();
        var sw          = Stopwatch.StartNew();
        int rxCount     = 0, matchCount = 0, mismatchCount = 0, lostCount = 0;
        double totalLat = 0;

        try
        {
            int idx   = 0;
            int total = frames.Count * config.Count;

            for (int rep = 0; rep < config.Count && !ct.IsCancellationRequested; rep++)
            {
                foreach (var frame in frames)
                {
                    if (ct.IsCancellationRequested) break;

                    // 잔류 패킷 제거
                    while (rxQueue.TryDequeue(out _)) { }
                    while (rxSignal.CurrentCount > 0) rxSignal.Wait(0);

                    var record = new PacketValidationRecord
                    {
                        Index     = idx++,
                        SentBytes = (byte[])frame.Clone()
                    };

                    long txTick = Stopwatch.GetTimestamp();

                    try { txDevice.SendPacket(frame); }
                    catch (Exception ex)
                    {
                        record.Status = PacketValidationStatus.Lost;
                        record.Note   = $"전송 오류: {ex.Message}";
                        records.Add(record);
                        lostCount++;
                        progress?.Report(record);
                        continue;
                    }

                    // ── 수신 대기 ──────────────────────────────────────────────
                    var deadline = DateTime.UtcNow.AddMilliseconds(config.TimeoutMs);
                    bool found   = false;

                    while (!found && DateTime.UtcNow < deadline && !ct.IsCancellationRequested)
                    {
                        int remainMs = Math.Max(1, (int)(deadline - DateTime.UtcNow).TotalMilliseconds);
                        bool signaled = await rxSignal.WaitAsync(remainMs, ct).ConfigureAwait(false);
                        if (!signaled) break;

                        if (!rxQueue.TryDequeue(out var rx)) continue;

                        double latMs = (rx.ticks - txTick) * 1000.0 / Stopwatch.Frequency;

                        if (IsMatch(frame, rx.data, config.MatchMode))
                        {
                            record.ReceivedBytes = rx.data;
                            record.Status        = PacketValidationStatus.Matched;
                            record.LatencyMs     = latMs;
                            rxCount++;
                            matchCount++;
                            totalLat += latMs;
                            found = true;
                        }
                        else
                        {
                            record.ReceivedBytes = rx.data;
                            record.Status        = PacketValidationStatus.Mismatch;
                            record.LatencyMs     = latMs;
                            record.Note          = $"수신 {rx.data.Length}B ≠ 전송 {frame.Length}B";
                            rxCount++;
                            mismatchCount++;
                            found = true;
                        }
                    }

                    if (!found && record.Status == PacketValidationStatus.Pending)
                    {
                        record.Status = PacketValidationStatus.Lost;
                        lostCount++;
                    }

                    records.Add(record);
                    progress?.Report(record);

                    if (config.InterPacketMs > 0 && idx < total)
                    {
                        try { await Task.Delay(config.InterPacketMs, ct).ConfigureAwait(false); }
                        catch (OperationCanceledException) { break; }
                    }
                }
            }
        }
        finally
        {
            rxDevice.OnPacketArrival -= OnArrival;
            try { rxDevice.StopCapture(); rxDevice.Close(); } catch { }
            if (!sameDevice)
                try { txDevice.Close(); } catch { }
            rxSignal.Dispose();
        }

        sw.Stop();

        var summary = new ValidationSummary
        {
            TxCount       = records.Count,
            RxCount       = rxCount,
            MatchCount    = matchCount,
            MismatchCount = mismatchCount,
            LostCount     = lostCount,
            ElapsedMs     = sw.Elapsed.TotalMilliseconds,
            AvgLatencyMs  = matchCount > 0 ? totalLat / matchCount : 0
        };

        return (summary, records);
    }

    private static bool IsMatch(byte[] sent, byte[] recv, ValidationMatchMode mode) =>
        mode switch
        {
            ValidationMatchMode.Exact =>
                sent.AsSpan().SequenceEqual(recv),
            ValidationMatchMode.Payload =>
                sent.Length >= 14 && recv.Length >= 14 &&
                sent.AsSpan(14).SequenceEqual(recv.AsSpan(14)),
            ValidationMatchMode.DstMacAndPayload =>
                sent.Length >= 14 && recv.Length >= 14 &&
                sent.AsSpan(0, 6).SequenceEqual(recv.AsSpan(0, 6)) &&
                sent.AsSpan(14).SequenceEqual(recv.AsSpan(14)),
            _ => sent.AsSpan().SequenceEqual(recv)
        };
}
