using System.Collections.ObjectModel;
using System.Text;
using System.Windows.Input;
using EthernetPacketGenerator.Commands;
using EthernetPacketGenerator.Services;
using Microsoft.Win32;
using SharpPcap;

namespace EthernetPacketGenerator.ViewModels;

public class CaptureRowViewModel : ViewModelBase
{
    public int    No          { get; init; }
    public string Time        { get; init; } = string.Empty;
    public string Source      { get; init; } = string.Empty;
    public string Destination { get; init; } = string.Empty;
    public string Protocol    { get; init; } = string.Empty;
    public int    Length      { get; init; }
    public string Info        { get; init; } = string.Empty;
    public byte[] Data        { get; init; } = Array.Empty<byte>();
}

public class CaptureViewModel : ViewModelBase
{
    private readonly PacketCaptureService _service = new();
    private bool _isCapturing;
    private string _statusMessage = "Ready";
    private string _filterText = string.Empty;
    private ILiveDevice? _device;
    private int _counter;
    private string _selectedHex = string.Empty;

    public ObservableCollection<CaptureRowViewModel> CapturedPackets { get; } = new();
    public ObservableCollection<TreeNode> DecodeRoots { get; } = new();

    public string SelectedHex
    {
        get => _selectedHex;
        private set => SetProperty(ref _selectedHex, value);
    }

    private CaptureRowViewModel? _selectedPacket;
    public CaptureRowViewModel? SelectedPacket
    {
        get => _selectedPacket;
        set
        {
            SetProperty(ref _selectedPacket, value);
            var data = value?.Data ?? Array.Empty<byte>();
            UpdateDecodeAndHex(data);
            SelectedPacketChanged?.Invoke(this, data);
        }
    }

    // 캡처 행 선택 시 디코드 트리에 바이트 전달
    public event EventHandler<byte[]>? SelectedPacketChanged;

    public bool IsCapturing
    {
        get => _isCapturing;
        set => SetProperty(ref _isCapturing, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public string FilterText
    {
        get => _filterText;
        set => SetProperty(ref _filterText, value);
    }

    public ICommand StartCaptureCommand { get; }
    public ICommand StopCaptureCommand { get; }
    public ICommand ClearCommand { get; }
    public ICommand SavePcapngCommand { get; }

    public CaptureViewModel()
    {
        StartCaptureCommand  = new RelayCommand(StartCapture,  () => !IsCapturing && _device != null);
        StopCaptureCommand   = new RelayCommand(StopCapture,   () => IsCapturing);
        ClearCommand         = new RelayCommand(Clear);
        SavePcapngCommand    = new RelayCommand(SavePcapng,    () => CapturedPackets.Count > 0);

        _service.PacketCaptured += OnPacketCaptured;
    }

    public void SetDevice(ILiveDevice? device)
    {
        if (IsCapturing) StopCapture();
        _device = device;
    }

    private void StartCapture()
    {
        if (_device == null) return;
        try
        {
            _service.StartCapture(_device, FilterText);
            IsCapturing = true;
            StatusMessage = $"Capturing on {_device.Description}...";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Capture error: {ex.Message}";
        }
    }

    private void StopCapture()
    {
        _service.StopCapture();
        IsCapturing = false;
        StatusMessage = $"Stopped. {CapturedPackets.Count} packet(s) captured.";
    }

    private void Clear()
    {
        CapturedPackets.Clear();
        _counter = 0;
        StatusMessage = "Cleared.";
    }

    private void SavePcapng()
    {
        var dlg = new SaveFileDialog
        {
            Filter = "Pcapng Files (*.pcapng)|*.pcapng|All Files (*.*)|*.*",
            DefaultExt = "pcapng",
            FileName = $"capture_{DateTime.Now:yyyyMMdd_HHmmss}.pcapng"
        };
        if (dlg.ShowDialog() != true) return;

        try
        {
            var infos = CapturedPackets.Select(r => new CapturedPacketInfo
            {
                Timestamp   = DateTime.Parse(r.Time),
                Length      = r.Length,
                Data        = r.Data,
                Protocol    = r.Protocol,
                Source      = r.Source,
                Destination = r.Destination,
                Info        = r.Info
            });
            PacketCaptureService.SavePcapng(infos, dlg.FileName);
            StatusMessage = $"Saved: {dlg.FileName}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Save error: {ex.Message}";
        }
    }

    private void OnPacketCaptured(object? sender, CapturedPacketInfo info)
    {
        System.Windows.Application.Current.Dispatcher.Invoke(() =>
        {
            _counter++;
            CapturedPackets.Add(new CaptureRowViewModel
            {
                No          = _counter,
                Time        = info.Timestamp.ToString("HH:mm:ss.ffffff"),
                Source      = info.Source,
                Destination = info.Destination,
                Protocol    = info.Protocol,
                Length      = info.Length,
                Info        = info.Info,
                Data        = info.Data
            });
            // 최대 5000개 유지
            if (CapturedPackets.Count > 5000)
                CapturedPackets.RemoveAt(0);
        });
    }

    private void UpdateDecodeAndHex(byte[] data)
    {
        DecodeRoots.Clear();
        if (data.Length > 0)
        {
            var nodes = ProtocolDecoder.Decode(data);
            foreach (var n in nodes)
                DecodeRoots.Add(n);
        }
        SelectedHex = data.Length > 0 ? BuildHexDump(data) : string.Empty;
    }

    private static string BuildHexDump(byte[] data)
    {
        const int bytesPerRow = 16;
        var sb = new StringBuilder();
        for (int i = 0; i < data.Length; i += bytesPerRow)
        {
            sb.Append($"{i:X4}  ");
            int count = Math.Min(bytesPerRow, data.Length - i);
            for (int j = 0; j < bytesPerRow; j++)
            {
                if (j < count) sb.Append($"{data[i + j]:X2} ");
                else           sb.Append("   ");
                if (j == 7)    sb.Append(' ');
            }
            sb.Append("  ");
            for (int j = 0; j < count; j++)
            {
                char c = (char)data[i + j];
                sb.Append(c >= 0x20 && c < 0x7F ? c : '.');
            }
            sb.AppendLine();
        }
        return sb.ToString();
    }
}
