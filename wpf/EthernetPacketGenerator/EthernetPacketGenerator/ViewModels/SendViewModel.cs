using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Windows.Input;
using System.Windows.Threading;
using EthernetPacketGenerator.Commands;
using EthernetPacketGenerator.Models;
using EthernetPacketGenerator.Services;
using SharpPcap;

namespace EthernetPacketGenerator.ViewModels;

public class SendViewModel : ViewModelBase
{
    private readonly PacketSendService _sendService;
    private ILiveDevice? _selectedInterface;
    private ObservableCollection<SequenceItem>? _sequence;

    private bool   _isSendingSelected;
    private bool   _isSendingList;
    private bool   _repeatEnabled;
    private int    _cyclePeriodMs = 5000;

    private string _startTime = "-";
    private string _endTime   = "-";
    private string _cycleTime       = "-";
    private string _estimatedTimeMs = "-";   // expected one-pass duration
    private string _passResultLabel = "-";   // "초과" or "여유"
    private string _passResultValue = "-";   // actual time value
    private bool   _isOverrun;               // drives colour in XAML
    private long   _cumulativeOverrunMs;     // accumulated overrun across repeats
    private int    _sentPackets;
    private long   _sentBytes;

    private CancellationTokenSource? _ctsSelected;
    private CancellationTokenSource? _ctsList;
    private DateTime  _sendStart;
    private Stopwatch _cycleWatch = new();
    private DispatcherTimer? _uiTimer;

    // ── Interfaces ──────────────────────────────────────────────────────────
    public ObservableCollection<ILiveDevice> Interfaces { get; } = new();

    /// <summary>체크박스+Default 라디오 포함 인터페이스 목록 (C 옵션)</summary>
    public ObservableCollection<InterfaceEntry> InterfaceEntries { get; } = new();

    public ILiveDevice? SelectedInterface
    {
        get => _selectedInterface;
        set
        {
            SetProperty(ref _selectedInterface, value);
            OnPropertyChanged(nameof(SelectedInterfaceName));
            if (value != null) _sendService.OpenDevice(value);
            SyncLabServer();
        }
    }

    public string SelectedInterfaceName => GetShortName(_selectedInterface);

    /// <summary>활성(IsActive=true) 인터페이스 목록을 반환한다.</summary>
    public IReadOnlyList<InterfaceEntry> ActiveEntries =>
        InterfaceEntries.Where(e => e.IsActive).ToList();

    /// <summary>ShortName으로 InterfaceEntry 룩업. 없으면 Default 반환.</summary>
    public InterfaceEntry? FindEntry(string? shortName) =>
        string.IsNullOrEmpty(shortName)
            ? InterfaceEntries.FirstOrDefault(e => e.IsDefault)
            : InterfaceEntries.FirstOrDefault(e => e.ShortName == shortName)
              ?? InterfaceEntries.FirstOrDefault(e => e.IsDefault);

    private void SyncLabServer()
    {
        if (System.Windows.Application.Current is not App app) return;
        var def = InterfaceEntries.FirstOrDefault(e => e.IsDefault);
        app.LabServer.SelectedInterfaceName  = GetShortName(def?.Device ?? _selectedInterface);
        app.LabServer.ActiveDevice           = def?.Device ?? _selectedInterface;
        app.LabServer.ActiveInterfaceEntries = InterfaceEntries.ToList();
    }

    public static string GetShortName(ILiveDevice? dev)
    {
        if (dev == null) return "(no interface)";
        var desc = dev.Description ?? dev.Name ?? string.Empty;
        var idx  = desc.LastIndexOf('{');
        if (idx > 0) desc = desc[..idx].TrimEnd(' ', '\\', '_');
        return desc.Length > 0 ? desc : (dev.Name ?? "(unknown)");
    }

    // ── Send state ───────────────────────────────────────────────────────────
    public bool IsSendingSelected
    {
        get => _isSendingSelected;
        set { SetProperty(ref _isSendingSelected, value); OnPropertyChanged(nameof(IsSending)); OnPropertyChanged(nameof(SendSelectedLabel)); }
    }

    public bool IsSendingList
    {
        get => _isSendingList;
        set { SetProperty(ref _isSendingList, value); OnPropertyChanged(nameof(IsSending)); OnPropertyChanged(nameof(SendListLabel)); }
    }

    public bool IsSending => _isSendingSelected || _isSendingList;

    public bool RepeatEnabled
    {
        get => _repeatEnabled;
        set => SetProperty(ref _repeatEnabled, value);
    }

    public int CyclePeriodMs
    {
        get => _cyclePeriodMs;
        set { SetProperty(ref _cyclePeriodMs, Math.Max(1, value)); RecalcEstimatedTime(); }
    }

    // ── Button labels ────────────────────────────────────────────────────────
    public string SendSelectedLabel => IsSendingSelected ? "■  Stop" : "▶  Send Selected";
    public string SendListLabel     => IsSendingList     ? "■  Stop" : "▶  Send List";

    // ── Status ───────────────────────────────────────────────────────────────
    public string StartTime
    {
        get => _startTime;
        set => SetProperty(ref _startTime, value);
    }

    public string EndTime
    {
        get => _endTime;
        set => SetProperty(ref _endTime, value);
    }

    public string CycleTime
    {
        get => _cycleTime;
        set => SetProperty(ref _cycleTime, value);
    }

    // Estimated one-pass duration (packets wire time + delay events)
    public string EstimatedTimeMs
    {
        get => _estimatedTimeMs;
        set => SetProperty(ref _estimatedTimeMs, value);
    }

    // "초과" or "여유"
    public string PassResultLabel
    {
        get => _passResultLabel;
        set => SetProperty(ref _passResultLabel, value);
    }

    // Time value next to the label
    public string PassResultValue
    {
        get => _passResultValue;
        set => SetProperty(ref _passResultValue, value);
    }

    // False = green (여유), True = red (초과)
    public bool IsOverrun
    {
        get => _isOverrun;
        set => SetProperty(ref _isOverrun, value);
    }

    public int SentPackets
    {
        get => _sentPackets;
        set => SetProperty(ref _sentPackets, value);
    }

    public long SentBytes
    {
        get => _sentBytes;
        set => SetProperty(ref _sentBytes, value);
    }

    // ── Commands ─────────────────────────────────────────────────────────────
    public ICommand SendSelectedCommand      { get; }
    public ICommand SendListCommand          { get; }
    public ICommand RefreshInterfacesCommand { get; }

    public SendViewModel()
    {
        _sendService = new PacketSendService();
        _sendService.PacketSent += (_, len) =>
            System.Windows.Application.Current.Dispatcher.Invoke(() =>
            {
                SentPackets++;
                SentBytes += len;
            });
        _sendService.SendError += (_, msg) =>
            System.Windows.Application.Current.Dispatcher.Invoke(() =>
                StartTime = $"Error: {msg}");

        SendSelectedCommand = new RelayCommand(ToggleSendSelected,
            () => !IsSendingList && SelectedInterface != null &&
                  (_sequence?.Any(s => s.IsChecked && s.Kind == SequenceItemKind.Packet) ?? false));
        SendListCommand = new RelayCommand(ToggleSendList,
            () => !IsSendingSelected && SelectedInterface != null &&
                  (_sequence?.Any(s => s.Kind == SequenceItemKind.Packet) ?? false));
        RefreshInterfacesCommand = new RelayCommand(LoadInterfaces);

        LoadInterfaces();
    }

    public void SetSequence(ObservableCollection<SequenceItem> seq)
    {
        // Unsubscribe old
        if (_sequence != null)
        {
            _sequence.CollectionChanged -= OnSequenceChanged;
            foreach (var item in _sequence) UnsubscribeItem(item);
        }

        _sequence = seq;
        _sequence.CollectionChanged += OnSequenceChanged;
        foreach (var item in _sequence) SubscribeItem(item);
        RecalcEstimatedTime();
    }

    // ── Sequence change tracking for EstimatedTime ───────────────────────────
    private void OnSequenceChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.OldItems != null) foreach (SequenceItem i in e.OldItems) UnsubscribeItem(i);
        if (e.NewItems != null) foreach (SequenceItem i in e.NewItems) SubscribeItem(i);
        RecalcEstimatedTime();
    }

    private void SubscribeItem(SequenceItem item)
    {
        item.PropertyChanged += OnSequenceItemChanged;
        if (item.Packet != null) item.Packet.PropertyChanged += OnPacketChanged;
        if (item.Event  != null) item.Event.PropertyChanged  += OnEventChanged;
    }

    private void UnsubscribeItem(SequenceItem item)
    {
        item.PropertyChanged -= OnSequenceItemChanged;
        if (item.Packet != null) item.Packet.PropertyChanged -= OnPacketChanged;
        if (item.Event  != null) item.Event.PropertyChanged  -= OnEventChanged;
    }

    private void OnSequenceItemChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
        => RecalcEstimatedTime();

    private void OnPacketChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(PacketItem.TotalLength))
            RecalcEstimatedTime();
    }

    private void OnEventChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(SequenceEvent.DelayMs))
            RecalcEstimatedTime();
    }

    // ── Estimated time calculation ───────────────────────────────────────────
    // Wire time per packet (1 Gbps): preamble(8) + max(frame,64) + FCS(4) + IFG(12) bytes
    // Delay events: their DelayMs value
    private void RecalcEstimatedTime()
    {
        if (_sequence == null || _sequence.Count == 0)
        {
            EstimatedTimeMs = "-";
            return;
        }

        double totalMs = 0;
        foreach (var item in _sequence)
        {
            if (item.Kind == SequenceItemKind.Packet && item.Packet != null)
                totalMs += EthernetTiming.WireTimeMs(item.Packet.TotalLength);
            else if (item.Kind == SequenceItemKind.Event && item.Event != null)
                totalMs += item.Event.DelayMs;
        }

        EstimatedTimeMs = $"{totalMs:F3} ms";
    }

    // ── Send Selected ────────────────────────────────────────────────────────
    private void ToggleSendSelected()
    {
        if (IsSendingSelected) { StopSelected(); return; }
        if (GetCheckedItems().Count == 0) return;

        BeginSend(showCycle: false);
        IsSendingSelected = true;

        var token = (_ctsSelected = new CancellationTokenSource()).Token;
        Task.Run(async () =>
        {
            bool cancelled = false;
            do
            {
                var items = await System.Windows.Application.Current.Dispatcher
                    .InvokeAsync(() => GetCheckedItems());
                if (items.Count == 0) break;

                foreach (var item in items)
                {
                    if (token.IsCancellationRequested) { cancelled = true; break; }

                    if (item.Kind == SequenceItemKind.Packet && item.Packet != null)
                    {
                        var entry = await System.Windows.Application.Current.Dispatcher
                            .InvokeAsync(() => FindEntry(item.Packet.OutgoingInterfaceName));
                        _sendService.SendOnce(item.Packet.FullBytes, entry?.Device);
                    }
                    else if (item.Kind == SequenceItemKind.Event && item.Event != null)
                    {
                        try { await Task.Delay(item.Event.DelayMs, token).ConfigureAwait(false); }
                        catch (OperationCanceledException) { cancelled = true; break; }
                    }
                }

            } while (!cancelled && RepeatEnabled && !token.IsCancellationRequested);

            System.Windows.Application.Current.Dispatcher.Invoke(() =>
            {
                IsSendingSelected = false;
                EndSendStats();
            });
        }, token);
    }

    private List<SequenceItem> GetCheckedItems() =>
        _sequence?.Where(s => s.IsChecked).ToList() ?? new();

    private void StopSelected()
    {
        _ctsSelected?.Cancel();
        IsSendingSelected = false;
        EndSendStats();
    }

    // ── Send List ────────────────────────────────────────────────────────────
    private void ToggleSendList()
    {
        if (IsSendingList) { StopList(); return; }
        if (_sequence == null) return;

        BeginSend(showCycle: true);
        IsSendingList = true;

        _ctsList = new CancellationTokenSource();
        Task.Run(async () => await RunListLoop(_ctsList.Token), _ctsList.Token);
    }

    private async Task RunListLoop(CancellationToken token)
    {
        bool cancelled = false;
        var passSw = new Stopwatch();

        do
        {
            passSw.Restart();
            _cycleWatch.Restart();

            List<SequenceItem> items = await System.Windows.Application.Current.Dispatcher
                .InvokeAsync(() => _sequence!.ToList());

            foreach (var item in items)
            {
                if (token.IsCancellationRequested) { cancelled = true; break; }

                if (item.Kind == SequenceItemKind.Packet && item.Packet != null)
                {
                    var entry = await System.Windows.Application.Current.Dispatcher
                        .InvokeAsync(() => FindEntry(item.Packet.OutgoingInterfaceName));
                    _sendService.SendOnce(item.Packet.FullBytes, entry?.Device);
                }
                else if (item.Kind == SequenceItemKind.Event && item.Event != null)
                {
                    try { await Task.Delay(item.Event.DelayMs, token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { cancelled = true; break; }
                }
            }

            passSw.Stop();
            if (cancelled) break;

            // Compute overrun/margin for this pass
            var passMs    = passSw.ElapsedMilliseconds;
            var overrunMs = passMs - CyclePeriodMs;
            var overrun   = overrunMs > 0;

            if (overrun)
                _cumulativeOverrunMs += overrunMs;

            System.Windows.Application.Current.Dispatcher.Invoke(() =>
            {
                IsOverrun = overrun;
                if (overrun)
                {
                    PassResultLabel = "초과";
                    PassResultValue = RepeatEnabled
                        ? $"+{overrunMs}ms  (누적 +{_cumulativeOverrunMs}ms)"
                        : $"+{overrunMs}ms";
                }
                else
                {
                    PassResultLabel = "여유";
                    PassResultValue = $"{CyclePeriodMs - passMs}ms";
                }
            });

            if (!RepeatEnabled) break;

            // Wait for remaining cycle time; if overrun → start immediately
            var remainMs = (int)(CyclePeriodMs - passMs);
            if (remainMs > 0)
            {
                try { await Task.Delay(remainMs, token).ConfigureAwait(false); }
                catch (OperationCanceledException) { break; }
            }

        } while (!token.IsCancellationRequested);

        System.Windows.Application.Current.Dispatcher.Invoke(() =>
        {
            IsSendingList = false;
            EndSendStats();
        });
    }

    private void StopList()
    {
        _ctsList?.Cancel();
        IsSendingList = false;
        EndSendStats();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────
    private void BeginSend(bool showCycle)
    {
        SentPackets          = 0;
        SentBytes            = 0;
        _sendStart           = DateTime.Now;
        StartTime            = _sendStart.ToString("HH:mm:ss");
        EndTime              = "-";
        CycleTime            = showCycle ? "0.0s / -" : "-";
        PassResultLabel      = "-";
        PassResultValue      = "-";
        IsOverrun            = false;
        _cumulativeOverrunMs = 0;

        _cycleWatch.Reset();

        _uiTimer?.Stop();
        _uiTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
        _uiTimer.Tick += (_, _) =>
        {
            if (showCycle && _cycleWatch.IsRunning)
                CycleTime = $"{_cycleWatch.Elapsed.TotalSeconds:F1}s / {CyclePeriodMs / 1000.0:F1}s";
        };
        _uiTimer.Start();
    }

    private void EndSendStats()
    {
        _uiTimer?.Stop();
        _uiTimer = null;
        _cycleWatch.Stop();
        EndTime   = DateTime.Now.ToString("HH:mm:ss");
        CycleTime = "-";
    }

    private void LoadInterfaces()
    {
        // 기존 추가 인터페이스 닫기
        foreach (var e in InterfaceEntries.Where(e => !e.IsDefault))
            _sendService.CloseExtra(e.Device);

        Interfaces.Clear();
        InterfaceEntries.Clear();

        var (devices, error) = NetworkInterfaceService.GetInterfaces();
        foreach (var dev in devices)
        {
            Interfaces.Add(dev);
            var entry = new InterfaceEntry(dev, GetShortName(dev));
            entry.PropertyChanged += OnInterfaceEntryChanged;
            InterfaceEntries.Add(entry);
        }

        // 첫 번째를 Default + Active로 지정
        if (InterfaceEntries.Count > 0)
        {
            InterfaceEntries[0].IsDefault = true;
            InterfaceEntries[0].IsActive  = true;
        }

        var apiStatus = "";
        if (System.Windows.Application.Current is App app)
            apiStatus = app.LabServer.IsRunning
                ? $" | API :{app.LabServer.Port} ●"
                : " | API 시작 실패 ✕";

        if (error != null)
            StartTime = error + apiStatus;
        else if (InterfaceEntries.Count > 0)
        {
            SelectedInterface = InterfaceEntries[0].Device;
            StartTime = $"Ready — {InterfaceEntries.Count} interface(s){apiStatus}";
        }
    }

    private void OnInterfaceEntryChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (sender is not InterfaceEntry changed) return;

        if (e.PropertyName == nameof(InterfaceEntry.IsDefault) && changed.IsDefault)
        {
            // 라디오 버튼처럼 동작: 다른 항목의 IsDefault 해제
            foreach (var entry in InterfaceEntries)
                if (entry != changed) entry.IsDefault = false;

            // 기본 인터페이스 변경 → _sendService 및 LabServer 동기화
            SelectedInterface = changed.Device;
        }

        if (e.PropertyName == nameof(InterfaceEntry.IsActive))
        {
            if (changed.IsActive)
                _sendService.OpenExtra(changed.Device);
            else
                _sendService.CloseExtra(changed.Device);
            SyncLabServer();
        }
    }
}
