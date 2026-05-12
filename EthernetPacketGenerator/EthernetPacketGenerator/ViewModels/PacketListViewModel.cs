using System.Collections.ObjectModel;
using System.Windows.Input;
using EthernetPacketGenerator.Commands;
using EthernetPacketGenerator.Models;

namespace EthernetPacketGenerator.ViewModels;

public class PacketListViewModel : ViewModelBase
{
    private PacketItem? _selectedPacket;
    private SequenceItem? _selectedSequenceItem;
    private ObservableCollection<InterfaceEntry> _interfaceEntries = new();

    // Flat sequence: packets + events interleaved
    public ObservableCollection<SequenceItem> Sequence { get; } = new();

    /// <summary>SendViewModel.InterfaceEntries 참조 — PacketListView의 Interface 드롭다운용</summary>
    public ObservableCollection<InterfaceEntry> InterfaceEntries
    {
        get => _interfaceEntries;
        set
        {
            if (_interfaceEntries != null)
                _interfaceEntries.CollectionChanged -= OnInterfaceEntriesChanged;
            SetProperty(ref _interfaceEntries, value);
            if (_interfaceEntries != null)
                _interfaceEntries.CollectionChanged += OnInterfaceEntriesChanged;
            OnPropertyChanged(nameof(InterfaceOptions));
        }
    }

    private void OnInterfaceEntriesChanged(object? sender,
        System.Collections.Specialized.NotifyCollectionChangedEventArgs e)
        => OnPropertyChanged(nameof(InterfaceOptions));

    /// <summary>
    /// PacketList ComboBox용 목록: 맨 앞에 "(Default)" sentinel 항목 포함.
    /// ShortName = "" → OutgoingInterfaceName = null (Default 동작)
    /// </summary>
    public IEnumerable<InterfaceEntry> InterfaceOptions =>
        Enumerable.Repeat(
            new InterfaceEntry(null!, "") { IsDefaultSentinel = true }, 1)
        .Concat(_interfaceEntries);

    // Convenience view of only PacketItems (for Send, HexDump, etc.)
    public IEnumerable<PacketItem> Packets => Sequence
        .Where(s => s.Kind == SequenceItemKind.Packet)
        .Select(s => s.Packet!);

    public PacketItem? SelectedPacket
    {
        get => _selectedPacket;
        set => SetProperty(ref _selectedPacket, value);
    }

    public SequenceItem? SelectedSequenceItem
    {
        get => _selectedSequenceItem;
        set
        {
            SetProperty(ref _selectedSequenceItem, value);
            SelectedPacket = value?.Kind == SequenceItemKind.Packet ? value.Packet : null;
        }
    }

    public ICommand AddPacketCommand       { get; }
    public ICommand DeleteItemCommand      { get; }
    public ICommand DuplicatePacketCommand { get; }
    public ICommand MoveUpCommand          { get; }
    public ICommand MoveDownCommand        { get; }
    public ICommand AddDelayEventCommand   { get; }

    public PacketListViewModel()
    {
        AddPacketCommand       = new RelayCommand(AddPacket);
        DeleteItemCommand      = new RelayCommand(DeleteItem,      () => SelectedSequenceItem != null);
        DuplicatePacketCommand = new RelayCommand(DuplicatePacket, () => SelectedPacket != null);
        MoveUpCommand          = new RelayCommand(MoveUp,          CanMoveUp);
        MoveDownCommand        = new RelayCommand(MoveDown,        CanMoveDown);
        AddDelayEventCommand   = new RelayCommand(AddDelayEvent);

        Sequence.CollectionChanged += (_, _) => ReIndex();

        AddPacket();
    }

    private void ReIndex()
    {
        for (int i = 0; i < Sequence.Count; i++)
            Sequence[i].Index = i;
    }

    public void AddPacket()
    {
        int insertAt = SelectedSequenceItem != null
            ? Sequence.IndexOf(SelectedSequenceItem) + 1
            : Sequence.Count;

        var packet = new PacketItem { Name = $"Packet{insertAt}" };
        var item = new SequenceItem(packet);

        Sequence.Insert(insertAt, item);
        SelectedSequenceItem = item;
    }

    private void AddDelayEvent()
    {
        var ev   = new SequenceEvent { DelayMs = 100 };
        var item = new SequenceItem(ev);

        int insertAt = SelectedSequenceItem != null
            ? Sequence.IndexOf(SelectedSequenceItem) + 1
            : Sequence.Count;
        Sequence.Insert(insertAt, item);
        SelectedSequenceItem = item;
    }

    private void DeleteItem()
    {
        if (SelectedSequenceItem == null) return;
        int idx = Sequence.IndexOf(SelectedSequenceItem);
        Sequence.Remove(SelectedSequenceItem);

        if (Sequence.Count > 0)
            SelectedSequenceItem = Sequence[Math.Max(0, idx - 1)];
        else
            SelectedSequenceItem = null;
    }

    private void DuplicatePacket()
    {
        if (SelectedPacket == null) return;
        var clone = new PacketItem();
        foreach (var block in SelectedPacket.Blocks)
        {
            var newBlock = PacketItem.CreateBlock(block.Type);
            newBlock.ImportBytes(block.Bytes, 0);
            clone.Blocks.Add(newBlock);
        }
        int idx = Sequence.IndexOf(SelectedSequenceItem!);
        int insertAt = idx + 1;
        clone.Name = $"Packet{insertAt}";
        var item = new SequenceItem(clone);
        Sequence.Insert(insertAt, item);
        SelectedSequenceItem = item;
    }

    private void MoveUp()
    {
        if (SelectedSequenceItem == null) return;
        int idx = Sequence.IndexOf(SelectedSequenceItem);
        if (idx > 0) Sequence.Move(idx, idx - 1);
    }

    private void MoveDown()
    {
        if (SelectedSequenceItem == null) return;
        int idx = Sequence.IndexOf(SelectedSequenceItem);
        if (idx < Sequence.Count - 1) Sequence.Move(idx, idx + 1);
    }

    private bool CanMoveUp()   => SelectedSequenceItem != null && Sequence.IndexOf(SelectedSequenceItem) > 0;
    private bool CanMoveDown() => SelectedSequenceItem != null && Sequence.IndexOf(SelectedSequenceItem) < Sequence.Count - 1;
}
