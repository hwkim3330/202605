using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using EthernetPacketGenerator.Models;
using EthernetPacketGenerator.ViewModels;

namespace EthernetPacketGenerator.Views;

public partial class PacketListView : UserControl
{
    public PacketListView() => InitializeComponent();

    // ── Inline rename (single click on Name cell) ──
    private void PacketName_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        BeginEdit(sender as FrameworkElement);
        e.Handled = true;
    }

    private void BeginEdit(FrameworkElement? element)
    {
        if (element == null) return;
        var grid = element.Parent as Grid;
        if (grid == null) return;

        var panel   = grid.FindName("PacketPanel") as UIElement;
        var editBox = grid.FindName("EditBox")     as TextBox;
        if (panel == null || editBox == null) return;

        panel.Visibility   = Visibility.Collapsed;
        editBox.Visibility = Visibility.Visible;
        editBox.SelectAll();
        editBox.Focus();
    }

    private void CommitEdit(TextBox editBox)
    {
        var grid  = editBox.Parent as Grid;
        var panel = grid?.FindName("PacketPanel") as UIElement;

        var newName = editBox.Text.Trim();
        if (!string.IsNullOrEmpty(newName) && editBox.DataContext is SequenceItem si && si.Packet != null)
            si.Packet.Name = newName;

        editBox.Visibility = Visibility.Collapsed;
        if (panel != null) panel.Visibility = Visibility.Visible;
    }

    private void EditBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (sender is not TextBox editBox) return;
        if (e.Key == Key.Enter)  { CommitEdit(editBox); e.Handled = true; }
        else if (e.Key == Key.Escape)
        {
            var grid  = editBox.Parent as Grid;
            var panel = grid?.FindName("PacketPanel") as UIElement;
            editBox.Visibility = Visibility.Collapsed;
            if (panel != null) panel.Visibility = Visibility.Visible;
            e.Handled = true;
        }
    }

    private void EditBox_LostFocus(object sender, RoutedEventArgs e)
    {
        if (sender is TextBox tb) CommitEdit(tb);
    }

    // ── Delay tile click → AddDelayEventCommand ──
    private void DelayTile_Click(object sender, MouseButtonEventArgs e)
    {
        if (DataContext is PacketListViewModel vm)
            vm.AddDelayEventCommand.Execute(null);
    }
}
