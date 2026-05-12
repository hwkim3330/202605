using System.Windows.Input;
using EthernetPacketGenerator.Commands;
using EthernetPacketGenerator.Models;
using EthernetPacketGenerator.Services;
using Microsoft.Win32;

namespace EthernetPacketGenerator.ViewModels;

public class MainViewModel : ViewModelBase
{
    private readonly Services.SerialPortService _serial = new();

    private ProtocolBlock? _selectedBlock;
    private int _selectedTabIndex;

    // Tab indices: 0=PacketGenerator, 1=Capture, 2=Automation, 3=HyperTerminal, 4=Settings

    public PacketListViewModel         PacketListVM         { get; } = new();
    public BlockBuilderViewModel       BlockBuilderVM       { get; } = new();
    public HexDumpViewModel            HexDumpVM            { get; } = new();
    public TreeDecodeViewModel         TreeDecodeVM         { get; } = new();
    public SendViewModel               SendVM               { get; }
    public HyperTerminalViewModel      HyperTerminalVM      { get; }
    public TestCaseManagerViewModel    TestCaseMgrVM        { get; }
    public PacketFlowMonitorViewModel  PacketFlowMonitorVM  { get; } = new();
    public CaptureViewModel            CaptureVM            { get; } = new();
    public AutomationViewModel         AutomationVM         { get; }

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

    public int SelectedTabIndex
    {
        get => _selectedTabIndex;
        set => SetProperty(ref _selectedTabIndex, value);
    }

    public ICommand SaveCommand  { get; }
    public ICommand LoadCommand  { get; }

    public MainViewModel()
    {
        HyperTerminalVM = new HyperTerminalViewModel(_serial);
        SendVM          = new SendViewModel(_serial);
        TestCaseMgrVM   = new TestCaseManagerViewModel(PacketListVM);
        AutomationVM    = new AutomationViewModel(PacketListVM, TestCaseMgrVM, PacketFlowMonitorVM);

        SendVM.SetLogCallback(line =>
            System.Windows.Application.Current.Dispatcher.Invoke(
                () => HyperTerminalVM.AppendTerminal(line)));

        SaveCommand = new RelayCommand(Save, () => PacketListVM.Packets.Any());
        LoadCommand = new RelayCommand(Load);

        PacketListVM.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(PacketListViewModel.SelectedPacket))
                OnSelectedPacketChanged(PacketListVM.SelectedPacket);
        };

        SendVM.SetSequence(PacketListVM.Sequence);
        PacketListVM.InterfaceEntries = SendVM.InterfaceEntries;

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
