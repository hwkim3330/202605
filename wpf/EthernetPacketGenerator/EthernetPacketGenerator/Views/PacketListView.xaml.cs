using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using EthernetPacketGenerator.Models;
using EthernetPacketGenerator.ViewModels;

namespace EthernetPacketGenerator.Views;

public partial class PacketListView : UserControl
{
    public PacketListView() => InitializeComponent();

    // ── Interface 팝업 체크박스 ──────────────────────────────────────────────

    /// <summary>StackPanel Loaded 시 인터페이스 체크박스 동적 생성</summary>
    private void IfaceCheckList_Loaded(object sender, RoutedEventArgs e)
    {
        if (sender is not StackPanel panel) return;
        RebuildInterfaceCheckboxes(panel);
    }

    private void RebuildInterfaceCheckboxes(StackPanel panel)
    {
        panel.Children.Clear();

        var seqItem = panel.Tag as SequenceItem;
        if (seqItem?.Packet == null) return;

        var vm = DataContext as PacketListViewModel;
        if (vm == null) return;

        var packet = seqItem.Packet;

        // "(Default)" 항목 — 모두 해제하는 버튼
        var clearBtn = new Button
        {
            Content = "(Default)  — 모두 해제",
            FontSize = 11,
            Padding = new Thickness(4, 2, 4, 2),
            Margin = new Thickness(0, 0, 0, 4),
            Background = new SolidColorBrush(Color.FromRgb(0x1E, 0x1E, 0x2E)),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0x3A, 0x3A, 0x5A)),
            Foreground = new SolidColorBrush(Color.FromRgb(0x88, 0xCC, 0xFF)),
            FontStyle = FontStyles.Italic
        };
        clearBtn.Click += (_, _) =>
        {
            packet.OutgoingInterfaceNames.Clear();
            packet.OnOutgoingInterfaceChanged();
            RebuildInterfaceCheckboxes(panel);
        };
        panel.Children.Add(clearBtn);

        // 인터페이스별 체크박스
        foreach (var entry in vm.InterfaceEntries)
        {
            if (entry.IsDefaultSentinel) continue;

            var cb = new CheckBox
            {
                Content = entry.ShortName,
                FontSize = 11,
                Margin = new Thickness(2, 2, 2, 2),
                Foreground = new SolidColorBrush(Color.FromRgb(0xCC, 0xCC, 0xFF)),
                IsChecked = packet.OutgoingInterfaceNames.Contains(entry.ShortName),
                Tag = (packet, entry.ShortName)
            };
            cb.Checked   += InterfaceCheckBox_Changed;
            cb.Unchecked += InterfaceCheckBox_Changed;
            panel.Children.Add(cb);
        }
    }

    private void InterfaceCheckBox_Changed(object sender, RoutedEventArgs e)
    {
        if (sender is not CheckBox cb) return;
        if (cb.Tag is not (PacketItem packet, string shortName)) return;

        if (cb.IsChecked == true)
            packet.OutgoingInterfaceNames.Add(shortName);
        else
            packet.OutgoingInterfaceNames.Remove(shortName);

        packet.OnOutgoingInterfaceChanged();
    }

    private void InterfaceToggle_Click(object sender, RoutedEventArgs e)
    {
        // ToggleButton이 속한 행의 StackPanel을 갱신
        if (sender is not ToggleButton toggle) return;
        var popup = FindVisualSibling<Popup>(toggle);
        if (popup == null) return;
        var panel = popup.Child is Border border
            ? border.Child as StackPanel
            : null;
        if (panel != null) RebuildInterfaceCheckboxes(panel);
    }

    private static T? FindVisualSibling<T>(DependencyObject element) where T : DependencyObject
    {
        var parent = VisualTreeHelper.GetParent(element);
        if (parent == null) return null;
        int count = VisualTreeHelper.GetChildrenCount(parent);
        for (int i = 0; i < count; i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T t) return t;
            var found = FindVisualDescendant<T>(child);
            if (found != null) return found;
        }
        return null;
    }

    private static T? FindVisualDescendant<T>(DependencyObject element) where T : DependencyObject
    {
        int count = VisualTreeHelper.GetChildrenCount(element);
        for (int i = 0; i < count; i++)
        {
            var child = VisualTreeHelper.GetChild(element, i);
            if (child is T t) return t;
            var found = FindVisualDescendant<T>(child);
            if (found != null) return found;
        }
        return null;
    }

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
