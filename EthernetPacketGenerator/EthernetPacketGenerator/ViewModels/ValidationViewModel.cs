using System.Collections.ObjectModel;
using System.Windows.Input;
using EthernetPacketGenerator.Commands;
using EthernetPacketGenerator.Models;
using EthernetPacketGenerator.Services;

namespace EthernetPacketGenerator.ViewModels;

public class ValidationResultRow : ViewModelBase
{
    public int    Index         { get; init; }
    public string StatusText    { get; init; } = string.Empty;
    public int    SentLength    { get; init; }
    public int    RecvLength    { get; init; }
    public string LatencyText   { get; init; } = string.Empty;
    public string Note          { get; init; } = string.Empty;
    public PacketValidationStatus Status { get; init; }
}

public class ValidationViewModel : ViewModelBase
{
    private readonly PacketValidationService _service = new();

    // ── 인터페이스 ────────────────────────────────────────────────────────────
    private ObservableCollection<InterfaceEntry> _interfaceEntries = new();
    public ObservableCollection<InterfaceEntry> InterfaceEntries
    {
        get => _interfaceEntries;
        private set => SetProperty(ref _interfaceEntries, value);
    }

    private InterfaceEntry? _txInterface;
    public InterfaceEntry? TxInterface
    {
        get => _txInterface;
        set => SetProperty(ref _txInterface, value);
    }

    private InterfaceEntry? _rxInterface;
    public InterfaceEntry? RxInterface
    {
        get => _rxInterface;
        set => SetProperty(ref _rxInterface, value);
    }

    private bool _sameInterface = true;
    public bool SameInterface
    {
        get => _sameInterface;
        set
        {
            SetProperty(ref _sameInterface, value);
            if (value) RxInterface = TxInterface;
            OnPropertyChanged(nameof(RxEnabled));
        }
    }

    public bool RxEnabled => !_sameInterface;

    // ── 설정 ─────────────────────────────────────────────────────────────────
    private int _count = 1;
    public int Count
    {
        get => _count;
        set => SetProperty(ref _count, Math.Max(1, value));
    }

    private int _timeoutMs = 2000;
    public int TimeoutMs
    {
        get => _timeoutMs;
        set => SetProperty(ref _timeoutMs, Math.Max(100, value));
    }

    private int _interPacketMs = 10;
    public int InterPacketMs
    {
        get => _interPacketMs;
        set => SetProperty(ref _interPacketMs, Math.Max(0, value));
    }

    private ValidationMatchMode _matchMode = ValidationMatchMode.Exact;
    public ValidationMatchMode MatchMode
    {
        get => _matchMode;
        set => SetProperty(ref _matchMode, value);
    }

    public IEnumerable<ValidationMatchMode> MatchModes =>
        Enum.GetValues<ValidationMatchMode>();

    private string _rxFilter = string.Empty;
    public string RxFilter
    {
        get => _rxFilter;
        set => SetProperty(ref _rxFilter, value);
    }

    private bool _selectedOnly;
    public bool SelectedOnly
    {
        get => _selectedOnly;
        set => SetProperty(ref _selectedOnly, value);
    }

    // ── 상태 ─────────────────────────────────────────────────────────────────
    private bool _isRunning;
    public bool IsRunning
    {
        get => _isRunning;
        set { SetProperty(ref _isRunning, value); OnPropertyChanged(nameof(RunLabel)); }
    }

    private int _progressValue;
    public int ProgressValue
    {
        get => _progressValue;
        set => SetProperty(ref _progressValue, value);
    }

    private int _progressMax = 1;
    public int ProgressMax
    {
        get => _progressMax;
        set => SetProperty(ref _progressMax, value);
    }

    private string _statusMessage = "준비";
    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public string RunLabel => IsRunning ? "■  중지" : "▶  검증 실행";

    // ── 결과 ─────────────────────────────────────────────────────────────────
    public ObservableCollection<ValidationResultRow> Results { get; } = new();

    private string _summaryTx        = "-";
    private string _summaryRx        = "-";
    private string _summaryMatch     = "-";
    private string _summaryMismatch  = "-";
    private string _summaryLost      = "-";
    private string _summaryLossRate  = "-";
    private string _summaryMatchRate = "-";
    private string _summaryLatency   = "-";
    private string _summaryElapsed   = "-";

    public string SummaryTx        { get => _summaryTx;        set => SetProperty(ref _summaryTx, value); }
    public string SummaryRx        { get => _summaryRx;        set => SetProperty(ref _summaryRx, value); }
    public string SummaryMatch     { get => _summaryMatch;     set => SetProperty(ref _summaryMatch, value); }
    public string SummaryMismatch  { get => _summaryMismatch;  set => SetProperty(ref _summaryMismatch, value); }
    public string SummaryLost      { get => _summaryLost;      set => SetProperty(ref _summaryLost, value); }
    public string SummaryLossRate  { get => _summaryLossRate;  set => SetProperty(ref _summaryLossRate, value); }
    public string SummaryMatchRate { get => _summaryMatchRate; set => SetProperty(ref _summaryMatchRate, value); }
    public string SummaryLatency   { get => _summaryLatency;   set => SetProperty(ref _summaryLatency, value); }
    public string SummaryElapsed   { get => _summaryElapsed;   set => SetProperty(ref _summaryElapsed, value); }

    // ── Commands ──────────────────────────────────────────────────────────────
    public ICommand RunCommand   { get; }
    public ICommand ClearCommand { get; }

    private ObservableCollection<SequenceItem>? _sequence;
    private CancellationTokenSource? _cts;

    public ValidationViewModel()
    {
        RunCommand   = new RelayCommand(ToggleRun);
        ClearCommand = new RelayCommand(Clear);
    }

    public void SetInterfaces(ObservableCollection<InterfaceEntry> entries)
    {
        InterfaceEntries = entries;
        entries.CollectionChanged += (_, _) => SyncDefault();
        SyncDefault();
    }

    public void SetSequence(ObservableCollection<SequenceItem> seq) => _sequence = seq;

    private void SyncDefault()
    {
        var def = InterfaceEntries.FirstOrDefault(e => e.IsDefault)
               ?? InterfaceEntries.FirstOrDefault();
        TxInterface = def;
        if (SameInterface) RxInterface = def;
    }

    private void ToggleRun()
    {
        if (IsRunning) { _cts?.Cancel(); return; }
        _ = RunAsync();
    }

    private async Task RunAsync()
    {
        if (TxInterface == null) { StatusMessage = "TX 인터페이스를 선택하세요."; return; }
        var rxDev = SameInterface ? TxInterface : RxInterface;
        if (rxDev == null) { StatusMessage = "RX 인터페이스를 선택하세요."; return; }

        var frames = GetFrames();
        if (frames.Count == 0) { StatusMessage = "패킷 목록이 비어 있습니다."; return; }

        Results.Clear();
        ResetSummary();
        IsRunning     = true;
        ProgressValue = 0;
        ProgressMax   = frames.Count * Count;
        StatusMessage = "검증 중...";

        _cts = new CancellationTokenSource();
        var config = new ValidationConfig
        {
            Count         = Count,
            TimeoutMs     = TimeoutMs,
            InterPacketMs = InterPacketMs,
            MatchMode     = MatchMode,
            RxFilter      = RxFilter
        };

        var prog = new Progress<PacketValidationRecord>(rec =>
        {
            Results.Add(new ValidationResultRow
            {
                Index       = rec.Index,
                StatusText  = rec.StatusText,
                Status      = rec.Status,
                SentLength  = rec.SentLength,
                RecvLength  = rec.ReceivedLength,
                LatencyText = rec.Status == PacketValidationStatus.Matched
                                  ? $"{rec.LatencyMs:F2} ms" : "-",
                Note        = rec.Note
            });
            ProgressValue++;
        });

        try
        {
            var (summary, _) = await _service.RunAsync(
                TxInterface.Device, rxDev.Device,
                frames, config, prog, _cts.Token);

            ApplySummary(summary);
            StatusMessage = $"완료 — {summary.MatchCount}/{summary.TxCount} 일치  " +
                            $"손실 {summary.LossRate:F1}%";
        }
        catch (OperationCanceledException) { StatusMessage = "중단됨."; }
        catch (Exception ex)              { StatusMessage = $"오류: {ex.Message}"; }
        finally                           { IsRunning = false; }
    }

    private List<byte[]> GetFrames()
    {
        if (_sequence == null) return new();
        var items = SelectedOnly
            ? _sequence.Where(s => s.IsChecked && s.Kind == SequenceItemKind.Packet)
            : _sequence.Where(s => s.Kind == SequenceItemKind.Packet);
        return items.Select(s => s.Packet!.FullBytes).ToList();
    }

    private void Clear()
    {
        Results.Clear();
        ProgressValue = 0;
        ResetSummary();
        StatusMessage = "준비";
    }

    private void ResetSummary()
    {
        SummaryTx = SummaryRx = SummaryMatch = SummaryMismatch =
        SummaryLost = SummaryLossRate = SummaryMatchRate =
        SummaryLatency = SummaryElapsed = "-";
    }

    private void ApplySummary(ValidationSummary s)
    {
        SummaryTx        = s.TxCount.ToString();
        SummaryRx        = s.RxCount.ToString();
        SummaryMatch     = s.MatchCount.ToString();
        SummaryMismatch  = s.MismatchCount.ToString();
        SummaryLost      = s.LostCount.ToString();
        SummaryLossRate  = $"{s.LossRate:F1} %";
        SummaryMatchRate = $"{s.MatchRate:F1} %";
        SummaryLatency   = s.AvgLatencyMs > 0 ? $"{s.AvgLatencyMs:F3} ms" : "-";
        SummaryElapsed   = $"{s.ElapsedMs:F0} ms";
    }
}
