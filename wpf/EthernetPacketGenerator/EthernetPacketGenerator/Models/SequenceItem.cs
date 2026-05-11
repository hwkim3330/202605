using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace EthernetPacketGenerator.Models;

public enum SequenceItemKind { Packet, Event }

public class SequenceItem : INotifyPropertyChanged
{
    public SequenceItemKind Kind   { get; }
    public PacketItem?      Packet { get; }
    public SequenceEvent?   Event  { get; }

    // 0-based index set by the list when collection changes
    private int _index;
    public int Index
    {
        get => _index;
        set { _index = value; OnPropertyChanged(); }
    }

    // Check state for "Send Selected" — only meaningful for Packet rows
    private bool _isChecked;
    public bool IsChecked
    {
        get => _isChecked;
        set { _isChecked = value; OnPropertyChanged(); }
    }

    // Flat properties for direct ListView column binding (avoids nested path refresh issues)
    public string DisplayName        => Packet?.Name            ?? (Event?.DisplayLabel ?? "");
    public string DisplaySrcMac      => Packet?.SrcMac          ?? "";
    public string DisplayDstMac      => Packet?.DstMac          ?? "";
    public string DisplayProtocol    => Packet?.ProtocolSummary ?? "";
    public string DisplayDescription => Packet?.PacketDescription ?? (Event?.DisplayLabel ?? "");
    public string DisplayInterface   => Packet?.OutgoingInterfaceName ?? "Default";

    public SequenceItem(PacketItem packet)
    {
        Kind   = SequenceItemKind.Packet;
        Packet = packet;
        packet.PropertyChanged += OnPacketChanged;
    }

    public SequenceItem(SequenceEvent ev)
    {
        Kind  = SequenceItemKind.Event;
        Event = ev;
        ev.PropertyChanged += (_, _) =>
        {
            OnPropertyChanged(nameof(DisplayName));
            OnPropertyChanged(nameof(DisplayDescription));
        };
    }

    private void OnPacketChanged(object? sender, PropertyChangedEventArgs e)
    {
        OnPropertyChanged(nameof(DisplayName));
        OnPropertyChanged(nameof(DisplaySrcMac));
        OnPropertyChanged(nameof(DisplayDstMac));
        OnPropertyChanged(nameof(DisplayProtocol));
        OnPropertyChanged(nameof(DisplayDescription));
        OnPropertyChanged(nameof(DisplayInterface));
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnPropertyChanged([CallerMemberName] string? n = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
}
