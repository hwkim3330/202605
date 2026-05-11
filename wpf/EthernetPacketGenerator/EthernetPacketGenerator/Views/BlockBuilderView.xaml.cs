using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using EthernetPacketGenerator.Models;
using EthernetPacketGenerator.ViewModels;

namespace EthernetPacketGenerator.Views;

public partial class BlockBuilderView : UserControl
{
    // ── drag state ──────────────────────────────────────────────────────────
    private ProtocolBlock?     _pendingDragBlock;
    private Point              _mouseDownPosOnThis;

    private bool               _isDragging;
    private ProtocolBlock?     _dragBlock;
    private DragAdornerWindow? _adorner;
    private int                _insertIdx = -1;

    private static readonly Point CenterOffset =
        new(DragAdornerWindow.ChipW / 2, DragAdornerWindow.ChipH / 2);

    internal static BlockBuilderView? ActiveDropTarget;

    public event EventHandler<ProtocolBlock?>? SelectedBlockChanged;

    public BlockBuilderView()
    {
        InitializeComponent();
        Loaded   += (_, _) => ActiveDropTarget = this;
        Unloaded += (_, _) => { if (ActiveDropTarget == this) ActiveDropTarget = null; };
    }

    private BlockBuilderViewModel? VM => DataContext as BlockBuilderViewModel;

    // ══════════════════════════════════════════════════════════════════════
    //  DOWN
    // ══════════════════════════════════════════════════════════════════════
    private void Block_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        var block = FindBlock(e.OriginalSource);
        if (block == null) return;

        _pendingDragBlock   = block;
        _mouseDownPosOnThis = e.GetPosition(this);
        _isDragging         = false;

        SelectedBlockChanged?.Invoke(this, block);
        CaptureMouse();
    }

    // ══════════════════════════════════════════════════════════════════════
    //  MOVE
    // ══════════════════════════════════════════════════════════════════════
    private void Root_MouseMove(object sender, MouseEventArgs e)
    {
        if (_pendingDragBlock == null && !_isDragging) return;
        if (e.LeftButton != MouseButtonState.Pressed) { CancelDrag(); return; }

        if (!_isDragging)
        {
            var pos = e.GetPosition(this);
            bool over =
                Math.Abs(pos.X - _mouseDownPosOnThis.X) > SystemParameters.MinimumHorizontalDragDistance ||
                Math.Abs(pos.Y - _mouseDownPosOnThis.Y) > SystemParameters.MinimumVerticalDragDistance;
            if (!over) return;

            _isDragging       = true;
            _dragBlock        = _pendingDragBlock;
            _pendingDragBlock = null;

            _adorner = DragAdornerWindow.Create(_dragBlock!);
            _adorner.PlaceAtCursor(CenterOffset);
            _adorner.Show();
        }

        _adorner?.PlaceAtCursor(CenterOffset);

        var ptInList = e.GetPosition(BlockList);
        _insertIdx = CalcInsertIdx(ptInList);
        if (new Rect(-20, -40, BlockList.ActualWidth + 40, BlockList.ActualHeight + 80).Contains(ptInList))
            ShowDropIndicator(_insertIdx);
        else
            HideDropIndicator();

        e.Handled = true;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  UP
    // ══════════════════════════════════════════════════════════════════════
    private void Root_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        ReleaseMouseCapture();
        if (!_isDragging || _dragBlock == null) { ResetDragState(); return; }
        FinishDrag();
    }

    // ══════════════════════════════════════════════════════════════════════
    //  WPF DragDrop (palette fallback)
    // ══════════════════════════════════════════════════════════════════════
    private void OnBlockDrop(object sender, DragEventArgs e)
    {
        HideDropIndicator();
        if (VM == null) return;
        if (!e.Data.GetDataPresent("ProtocolType")) { e.Effects = DragDropEffects.None; return; }

        var type = (ProtocolType)e.Data.GetData("ProtocolType");
        int idx;
        try   { idx = CalcInsertIdx(e.GetPosition(BlockList)); }
        catch { idx = VM.Blocks?.Count ?? 0; }

        VM.InsertBlock(type, idx);
        e.Effects = DragDropEffects.Copy;
        e.Handled = true;
    }

    private void OnDragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent("ProtocolType"))
        {
            e.Effects = DragDropEffects.Copy;
            ShowDropIndicator(CalcInsertIdx(e.GetPosition(BlockList)));
        }
        else
        {
            e.Effects = DragDropEffects.None;
            HideDropIndicator();
        }
        e.Handled = true;
    }

    private void OnDragLeave(object sender, DragEventArgs e)
    {
        if (!new Rect(0, 0, ActualWidth, ActualHeight).Contains(e.GetPosition(this)))
            HideDropIndicator();
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Called by ProtocolPaletteView
    // ══════════════════════════════════════════════════════════════════════
    internal void PaletteDragOver(ProtocolType type, Point dipPt)
    {
        if (IsInsideControlDip(dipPt))
        {
            DragAdornerWindow.GetCursorScreenPx(out int sx, out int sy);
            var ptInList = BlockList.PointFromScreen(new Point(sx, sy));
            _insertIdx = CalcInsertIdx(ptInList);
            ShowDropIndicator(_insertIdx);
        }
        else
        {
            _insertIdx = -1;
            HideDropIndicator();
        }
    }

    internal void PaletteDrop(ProtocolType type, Point dipPt)
    {
        HideDropIndicator();
        if (VM == null || !IsInsideControlDip(dipPt)) return;

        DragAdornerWindow.GetCursorScreenPx(out int sx, out int sy);
        var ptInList = BlockList.PointFromScreen(new Point(sx, sy));
        VM.InsertBlock(type, CalcInsertIdx(ptInList));
        _insertIdx = -1;
    }

    internal void PaletteDragLeave()
    {
        _insertIdx = -1;
        HideDropIndicator();
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Drag state helpers
    // ══════════════════════════════════════════════════════════════════════
    private void CancelDrag()
    {
        ReleaseMouseCapture();
        if (_isDragging && _dragBlock != null && VM?.Blocks != null)
        {
            if (_insertIdx >= 0)
            {
                int from = VM.Blocks.IndexOf(_dragBlock);
                int dest = _insertIdx > from ? _insertIdx - 1 : _insertIdx;
                if (from >= 0 && dest != from)
                    VM.Blocks.Move(from, dest);
            }
            else
            {
                VM.RemoveBlockCommand.Execute(_dragBlock);
            }
        }
        ResetDragState();
    }

    private void FinishDrag()
    {
        CloseAdorner();
        HideDropIndicator();
        ResetDragState();
    }

    private void ResetDragState()
    {
        _pendingDragBlock = null;
        _isDragging       = false;
        _dragBlock        = null;
        _insertIdx        = -1;
        CloseAdorner();
        HideDropIndicator();
    }

    private void CloseAdorner() { _adorner?.Close(); _adorner = null; }

    // ══════════════════════════════════════════════════════════════════════
    //  Drop indicator
    // ══════════════════════════════════════════════════════════════════════
    private void ShowDropIndicator(int insertIdx)
    {
        if (DropIndicatorCanvas == null) return;
        Canvas.SetLeft(DropIndicatorLine, GetIndicatorX(insertIdx) - 1.5);
        DropIndicatorCanvas.Visibility = Visibility.Visible;
    }

    private void HideDropIndicator()
    {
        if (DropIndicatorCanvas != null)
            DropIndicatorCanvas.Visibility = Visibility.Collapsed;
    }

    private double GetIndicatorX(int insertIdx)
    {
        var panel = FindVisualChild<StackPanel>(BlockList);
        if (panel == null || panel.Children.Count == 0) return 6;
        try
        {
            if (insertIdx <= 0)
            {
                if (panel.Children[0] is FrameworkElement first)
                    return first.TransformToAncestor(DropIndicatorCanvas)
                                .TransformBounds(new Rect(first.RenderSize)).Left;
                return 6;
            }

            int t = Math.Min(insertIdx - 1, panel.Children.Count - 1);
            if (panel.Children[t] is FrameworkElement child)
                return child.TransformToAncestor(DropIndicatorCanvas)
                            .TransformBounds(new Rect(child.RenderSize)).Right;
        }
        catch { }
        return 6;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Index calculation
    // ══════════════════════════════════════════════════════════════════════
    private int CalcInsertIdx(Point ptInBlockList)
    {
        if (VM?.Blocks == null) return 0;
        double x = ptInBlockList.X;

        var panel = FindVisualChild<StackPanel>(BlockList);
        if (panel == null) return VM.Blocks.Count;

        for (int i = 0; i < panel.Children.Count; i++)
        {
            if (panel.Children[i] is not FrameworkElement c) continue;
            try
            {
                var b = c.TransformToAncestor(BlockList).TransformBounds(new Rect(c.RenderSize));
                if (x < b.Left + b.Width / 2) return i;
            }
            catch { }
        }
        return panel.Children.Count;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Hit-test helpers
    // ══════════════════════════════════════════════════════════════════════
    private bool IsInsideControlDip(Point dipPt)
    {
        try
        {
            DragAdornerWindow.GetCursorScreenPx(out int sx, out int sy);
            var local = PointFromScreen(new Point(sx, sy));
            return new Rect(0, 0, ActualWidth, ActualHeight).Contains(local);
        }
        catch { return false; }
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Visual-tree helpers
    // ══════════════════════════════════════════════════════════════════════
    private static ProtocolBlock? FindBlock(object src)
    {
        var el = src as DependencyObject;
        while (el != null)
        {
            if (el is FrameworkElement fe && fe.DataContext is ProtocolBlock b) return b;
            el = VisualTreeHelper.GetParent(el);
        }
        return null;
    }

    private static T? FindVisualChild<T>(DependencyObject parent) where T : DependencyObject
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(parent); i++)
        {
            var child = VisualTreeHelper.GetChild(parent, i);
            if (child is T t) return t;
            var r = FindVisualChild<T>(child);
            if (r != null) return r;
        }
        return null;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Context-menu
    // ══════════════════════════════════════════════════════════════════════
    private void RemoveBlock_Click(object sender, RoutedEventArgs e)
    {
        if (sender is MenuItem mi && mi.Tag is ProtocolBlock block)
            VM?.RemoveBlockCommand.Execute(block);
    }

    private void MoveLeft_Click(object sender, RoutedEventArgs e)
    {
        if (sender is MenuItem mi && mi.Tag is ProtocolBlock block)
            VM?.MoveBlockLeftCommand.Execute(block);
    }

    private void MoveRight_Click(object sender, RoutedEventArgs e)
    {
        if (sender is MenuItem mi && mi.Tag is ProtocolBlock block)
            VM?.MoveBlockRightCommand.Execute(block);
    }
}
