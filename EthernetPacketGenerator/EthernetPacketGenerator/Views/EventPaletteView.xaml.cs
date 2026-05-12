using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using EthernetPacketGenerator.Models;
using EthernetPacketGenerator.ViewModels;

namespace EthernetPacketGenerator.Views;

public partial class EventPaletteView : UserControl
{
    public EventPaletteView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if (e.OldValue is PacketListViewModel oldVm)
            oldVm.PropertyChanged -= OnVmPropertyChanged;
        if (e.NewValue is PacketListViewModel newVm)
            newVm.PropertyChanged += OnVmPropertyChanged;

        RefreshEditor();
    }

    private void OnVmPropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(PacketListViewModel.SelectedSequenceItem))
            RefreshEditor();
    }

    private void RefreshEditor()
    {
        var vm = DataContext as PacketListViewModel;
        var ev = vm?.SelectedSequenceItem?.Event;

        EventEditor.Visibility = ev != null ? Visibility.Visible : Visibility.Collapsed;
        if (ev != null)
            DelayMsBox.Text = ev.DelayMs.ToString();
    }

    private void DelayTile_Click(object sender, MouseButtonEventArgs e)
    {
        if (DataContext is PacketListViewModel vm)
            vm.AddDelayEventCommand.Execute(null);
    }

    private void DelayMsBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        var vm = DataContext as PacketListViewModel;
        var ev = vm?.SelectedSequenceItem?.Event;
        if (ev == null) return;
        if (int.TryParse(DelayMsBox.Text, out int ms) && ms >= 0)
            ev.DelayMs = ms;
    }
}
