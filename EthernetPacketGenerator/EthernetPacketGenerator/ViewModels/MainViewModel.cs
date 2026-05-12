using System.Windows.Input;
using EthernetPacketGenerator.Commands;
using EthernetPacketGenerator.Models;
using EthernetPacketGenerator.Services;
using Microsoft.Win32;

namespace EthernetPacketGenerator.ViewModels;

public class MainViewModel : ViewModelBase
{
    private ProtocolBlock? _selectedBlock;

    public PacketListViewModel PacketListVM { get; } = new();
    public BlockBuilderViewModel BlockBuilderVM { get; } = new();
    public HexDumpViewModel HexDumpVM { get; } = new();
    public TreeDecodeViewModel TreeDecodeVM { get; } = new();
    public SendViewModel SendVM { get; } = new();
    public CaptureViewModel CaptureVM { get; } = new();
    public ValidationViewModel ValidationVM { get; } = new();

    public ProtocolBlock? SelectedBlock
    {
        get => _selectedBlock;
        set
        {
            SetProperty(ref _selectedBlock, value);
            BlockBuilderVM.SelectedBlock = value;
            HexDumpVM.SetHighlightedBlock(value);
        }
    }

    public ICommand SaveCommand { get; }
    public ICommand LoadCommand { get; }

    public MainViewModel()
    {
        SaveCommand = new RelayCommand(Save, () => PacketListVM.Packets.Any());
        LoadCommand = new RelayCommand(Load);

        PacketListVM.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(PacketListViewModel.SelectedPacket))
                OnSelectedPacketChanged(PacketListVM.SelectedPacket);
        };

        // Pass sequence to SendVM so it can iterate packets+events
        SendVM.SetSequence(PacketListVM.Sequence);

        // Share interface entries with PacketListVM for per-packet interface dropdown
        PacketListVM.InterfaceEntries = SendVM.InterfaceEntries;

        // CaptureVM follows selected interface
        SendVM.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(SendViewModel.SelectedInterface))
                CaptureVM.SetDevice(SendVM.SelectedInterface);
        };
        CaptureVM.SetDevice(SendVM.SelectedInterface);

        // ValidationVM gets interfaces + sequence
        ValidationVM.SetInterfaces(SendVM.InterfaceEntries);
        ValidationVM.SetSequence(PacketListVM.Sequence);

        if (PacketListVM.SelectedPacket != null)
            OnSelectedPacketChanged(PacketListVM.SelectedPacket);
    }

    private void OnSelectedPacketChanged(PacketItem? packet)
    {
        BlockBuilderVM.SetPacket(packet);
        HexDumpVM.SetPacket(packet);
        TreeDecodeVM.SetPacket(packet);
        SelectedBlock = null;
    }

    private void Save()
    {
        var dlg = new SaveFileDialog
        {
            Filter = "Packet Generator Files (*.epg)|*.epg|All Files (*.*)|*.*",
            DefaultExt = "epg"
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            PacketSerializationService.Save(PacketListVM.Packets, dlg.FileName);
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"Save failed: {ex.Message}", "Error",
                System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
        }
    }

    private void Load()
    {
        var dlg = new OpenFileDialog
        {
            Filter = "Packet Generator Files (*.epg)|*.epg|All Files (*.*)|*.*"
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            var packets = PacketSerializationService.Load(dlg.FileName);
            PacketListVM.Sequence.Clear();
            foreach (var p in packets)
                PacketListVM.Sequence.Add(new SequenceItem(p));

            if (PacketListVM.Packets.Any())
                PacketListVM.SelectedSequenceItem =
                    PacketListVM.Sequence.First(s => s.Kind == SequenceItemKind.Packet);
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show($"Load failed: {ex.Message}", "Error",
                System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
        }
    }
}
