using System.Collections.ObjectModel;
using System.Threading;
using System.Windows.Input;
using System.Windows.Threading;
using EthernetPacketGenerator.Commands;
using EthernetPacketGenerator.Models;
using PacketDotNet;
using SharpPcap;

namespace EthernetPacketGenerator.ViewModels;

public class CaptureViewModel : ViewModelBase
{
    public ObservableCollection<ILiveDevice> Interfaces { get; } = new();

    private ILiveDevice? _selectedInterface;
    public ILiveDevice? SelectedInterface
    {
        get => _selectedInterface;
        set
        {
            SetProperty(ref _selectedInterface, value);
            System.Windows.Application.Current?.Dispatcher.InvokeAsync(
                System.Windows.Input.CommandManager.InvalidateRequerySuggested,
                DispatcherPriority.Background);
        }
    }

    public ObservableCollection<CaptureRow> Packets { get; } = new();

    private bool _isCapturing;
    public bool IsCapturing
    {
        get => _isCapturing;
        private set
        {
            SetProperty(ref _isCapturing, value);
            System.Windows.Application.Current?.Dispatcher.InvokeAsync(
                System.Windows.Input.CommandManager.InvalidateRequerySuggested,
                DispatcherPriority.Background);
        }
    }

    private int _totalPackets;
    public int TotalPackets
    {
        get => _totalPackets;
        private set => SetProperty(ref _totalPackets, value);
    }

    private string _statusText = "Ready — select an interface and press Start.";
    public string StatusText
    {
        get => _statusText;
        set => SetProperty(ref _statusText, value);
    }

    public ICommand StartCommand { get; }
    public ICommand StopCommand  { get; }
    public ICommand ClearCommand { get; }

    private ILiveDevice? _activeDevice;
    private int          _seqNo;
    private DateTime     _captureStart;

    public CaptureViewModel()
    {
        LoadInterfaces();
        StartCommand = new RelayCommand(Start, () => !IsCapturing && SelectedInterface != null);
        StopCommand  = new RelayCommand(Stop,  () => IsCapturing);
        ClearCommand = new RelayCommand(Clear);
    }

    private void LoadInterfaces()
    {
        try
        {
            foreach (var dev in CaptureDeviceList.Instance)
                Interfaces.Add(dev);
            if (Interfaces.Count > 0)
                SelectedInterface = Interfaces[0];
        }
        catch { }
    }

    private void Start()
    {
        if (SelectedInterface == null) return;
        try
        {
            _seqNo        = 0;
            _captureStart = DateTime.Now;
            _activeDevice = SelectedInterface;
            _activeDevice.OnPacketArrival += OnPacketArrival;
            _activeDevice.Open(DeviceModes.Promiscuous, 1000);
            _activeDevice.StartCapture();
            IsCapturing = true;
            StatusText  = $"Capturing on {_activeDevice.Description ?? _activeDevice.Name}…";
        }
        catch (Exception ex)
        {
            StatusText    = $"Error: {ex.Message}";
            _activeDevice = null;
        }
    }

    private void Stop()
    {
        try { _activeDevice?.StopCapture(); } catch { }
        try { _activeDevice?.Close(); }       catch { }
        if (_activeDevice != null)
            _activeDevice.OnPacketArrival -= OnPacketArrival;
        _activeDevice = null;
        IsCapturing   = false;
        StatusText    = $"Stopped. {TotalPackets} packets captured.";
    }

    private void Clear()
    {
        Packets.Clear();
        TotalPackets = 0;
        _seqNo       = 0;
        StatusText   = "Cleared.";
    }

    private void OnPacketArrival(object sender, PacketCapture e)
    {
        var raw = e.GetPacket();
        var row = ParseRow(raw);
        System.Windows.Application.Current?.Dispatcher.InvokeAsync(() =>
        {
            if (Packets.Count >= 5000) Packets.RemoveAt(0);
            Packets.Add(row);
            TotalPackets++;
        }, DispatcherPriority.Background);
    }

    private CaptureRow ParseRow(RawCapture raw)
    {
        int    no       = Interlocked.Increment(ref _seqNo);
        double elapsed  = (DateTime.Now - _captureStart).TotalSeconds;
        string srcMac   = string.Empty;
        string dstMac   = string.Empty;
        string protocol = "Ethernet";
        string info     = string.Empty;
        int    length   = raw.Data.Length;

        try
        {
            var packet = Packet.ParsePacket(raw.LinkLayerType, raw.Data);
            if (packet is EthernetPacket eth)
            {
                srcMac = eth.SourceHardwareAddress?.ToString() ?? string.Empty;
                dstMac = eth.DestinationHardwareAddress?.ToString() ?? string.Empty;

                if (eth.PayloadPacket is ArpPacket arp)
                {
                    protocol = "ARP";
                    info     = $"Who has {arp.TargetProtocolAddress}? Tell {arp.SenderProtocolAddress}";
                }
                else if (eth.PayloadPacket is IPv4Packet ipv4)
                {
                    var src = ipv4.SourceAddress?.ToString() ?? "?";
                    var dst = ipv4.DestinationAddress?.ToString() ?? "?";
                    protocol = "IPv4";
                    info     = $"{src} → {dst}";

                    if (ipv4.PayloadPacket is UdpPacket udp)
                    {
                        protocol = "UDP";
                        info     = $"{src}:{udp.SourcePort} → {dst}:{udp.DestinationPort}  len={udp.Length}";
                    }
                    else if (ipv4.PayloadPacket is TcpPacket tcp)
                    {
                        protocol = "TCP";
                        string flags = string.Empty;
                        try
                        {
                            if (tcp.Synchronize)    flags += "S";
                            if (tcp.Acknowledgment) flags += "A";
                            if (tcp.Finished)       flags += "F";
                            if (tcp.Reset)          flags += "R";
                            if (tcp.Push)           flags += "P";
                        }
                        catch { }
                        info = $"{src}:{tcp.SourcePort} → {dst}:{tcp.DestinationPort}" +
                               (flags.Length > 0 ? $" [{flags}]" : string.Empty);
                    }
                    else if (ipv4.PayloadPacket != null)
                    {
                        protocol = $"IP/{(int)ipv4.Protocol}";
                    }
                }
                else if (eth.PayloadPacket is IPv6Packet ipv6)
                {
                    protocol = "IPv6";
                    info     = $"{ipv6.SourceAddress} → {ipv6.DestinationAddress}";
                }
            }
        }
        catch { /* 파싱 실패 — 기본값 유지 */ }

        return new CaptureRow
        {
            No       = no,
            Time     = elapsed.ToString("F4"),
            SrcMac   = srcMac,
            DstMac   = dstMac,
            Protocol = protocol,
            Length   = length,
            Info     = info
        };
    }
}
