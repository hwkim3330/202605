using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using EthernetPacketGenerator.Models;
using EthernetPacketGenerator.ViewModels;

namespace EthernetPacketGenerator.Views;

public partial class BlockBuilderView : UserControl
{
    private const int WM_LBUTTONUP = 0x0202;

    // ── drag state ──────────────────────────────────────────────────────────
    private ProtocolBlock?     _pendingDragBlock;
    private Point              _mouseDownPosOnThis;

    private bool               _isDragging;
    private ProtocolBlock?     _dragBlock;
    private DragAdornerWindow? _adorner;
    private int                _insertIdx = -1;

    // EndDrag guard flags ────────────────────────────────────────────────────
    // Prevents OnLostMouseCapture from double-applying the drop.
    private bool               _releasingCapture;
    // Suppresses OnLostMouseCapture while the adorner HWND is being created;
    // adorner.Show() can send WM_CANCELMODE and release SetCapture momentarily.
    private bool               _ignoreNextLostCapture;

    private static readonly Point CenterOffset =
        new(DragAdornerWindow.ChipW / 2, DragAdornerWindow.ChipH / 2);

    internal static BlockBuilderView? ActiveDropTarget;

    public event EventHandler<ProtocolBlock?>? SelectedBlockChanged;

    // Win32 메시지 훅 — adorner HWND 위에서 버튼을 놓는 경우에도
    // WM_LBUTTONUP을 확실히 감지하기 위해 메인 창의 HwndSource에 훅을 건다.
    private HwndSource? _hwndSource;

    public BlockBuilderView()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            ActiveDropTarget = this;
            // 최상위 Window의 HwndSource에 Win32 메시지 훅 등록
            if (Window.GetWindow(this) is Window w)
            {
                _hwndSource = HwndSource.FromHwnd(new WindowInteropHelper(w).Handle);
                _hwndSource?.AddHook(WndProc);
            }
        };
        Unloaded += (_, _) =>
        {
            if (ActiveDropTarget == this) ActiveDropTarget = null;
            _hwndSource?.RemoveHook(WndProc);
            _hwndSource = null;
        };
    }

    // Win32 WM_LBUTTONUP 훅 — WPF MouseLeftButtonUp이 adorner HWND에 가로막혀
    // 도달하지 못하는 경우를 위한 안전망.
    private IntPtr WndProc(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam, ref bool handled)
    {
        if (msg == WM_LBUTTONUP && _isDragging && _dragBlock != null)
        {
            DragAdornerWindow.GetCursorScreenPx(out int sx, out int sy);
            var ptInView = PointFromScreen(new Point(sx, sy));
            if (!new Rect(0, 0, ActualWidth, ActualHeight).Contains(ptInView))
                _insertIdx = -1;

            EndDrag();
        }
        return IntPtr.Zero;
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
        if (e.LeftButton != MouseButtonState.Pressed) { EndDrag(); return; }

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

            // adorner Show()가 WM_CANCELMODE를 동기적으로 보낼 수 있어
            // OnLostMouseCapture를 adorner 생성 완료 전에 fire시킬 수 있음.
            // _ignoreNextLostCapture 플래그로 이를 억제하고, 이후 재캡처.
            _ignoreNextLostCapture = true;
            _adorner = DragAdornerWindow.Create(_dragBlock!);
            _adorner.PlaceAtCursor(CenterOffset);
            _adorner.Show();
            _ignoreNextLostCapture = false;

            // Show() 중 WM_CANCELMODE로 캡처가 풀렸을 수 있으므로 재캡처
            if (!IsMouseCaptured)
                CaptureMouse();

            // 재캡처 후 현재 커서 위치를 Win32 기반으로 다시 평가
            UpdateInsertIdxFromCursor();
            return;
        }

        _adorner?.PlaceAtCursor(CenterOffset);
        UpdateInsertIdxFromCursor();

        e.Handled = true;
    }

    // Win32 GetCursorPos 기반으로 _insertIdx와 드롭 인디케이터를 갱신.
    // WPF MouseEventArgs 좌표 대신 Win32를 쓰는 이유:
    //   adorner Show() 이후 재캡처 상태에서도 정확한 화면 좌표를 얻기 위함.
    private void UpdateInsertIdxFromCursor()
    {
        DragAdornerWindow.GetCursorScreenPx(out int sx, out int sy);
        var ptInView = PointFromScreen(new Point(sx, sy));

        if (!new Rect(0, 0, ActualWidth, ActualHeight).Contains(ptInView))
        {
            _insertIdx = -1;
            HideDropIndicator();
        }
        else
        {
            var ptInList = BlockList.PointFromScreen(new Point(sx, sy));
            _insertIdx = CalcInsertIdx(ptInList);
            ShowDropIndicator(_insertIdx);
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    //  UP — Preview(tunnel) 단계에서 먼저 처리
    //  이유: adorner가 별도 HWND이기 때문에, adorner 위에서 마우스 버튼을
    //  놓으면 WM_LBUTTONUP이 adorner HWND로 가서 bubbling MouseLeftButtonUp이
    //  BlockBuilderView에 도달하지 않는다. PreviewMouseLeftButtonUp(tunneling)
    //  은 캡처된 요소에 항상 먼저 도달하므로 이쪽에서 처리한다.
    // ══════════════════════════════════════════════════════════════════════
    private void Root_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (!_isDragging || _dragBlock == null) { ResetDragState(); return; }

        // Win32 좌표로 최종 위치 재확인
        DragAdornerWindow.GetCursorScreenPx(out int sx, out int sy);
        var ptInView = PointFromScreen(new Point(sx, sy));
        if (!new Rect(0, 0, ActualWidth, ActualHeight).Contains(ptInView))
            _insertIdx = -1;

        EndDrag();
        e.Handled = true;
    }

    private void Root_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        // Preview 단계에서 이미 처리됨. 혹시 Preview가 누락된 경우를 위한 fallback.
        if (!_isDragging || _dragBlock == null) { ResetDragState(); return; }

        DragAdornerWindow.GetCursorScreenPx(out int sx, out int sy);
        var ptInView = PointFromScreen(new Point(sx, sy));
        if (!new Rect(0, 0, ActualWidth, ActualHeight).Contains(ptInView))
            _insertIdx = -1;

        EndDrag();
        e.Handled = true;
    }

    // ══════════════════════════════════════════════════════════════════════
    //  LOST CAPTURE — handles unexpected SetCapture release during drag
    // ══════════════════════════════════════════════════════════════════════
    protected override void OnLostMouseCapture(MouseEventArgs e)
    {
        base.OnLostMouseCapture(e);

        if (_isDragging && !_releasingCapture && !_ignoreNextLostCapture)
        {
            // 외부(예: 다른 윈도우 클릭, Alt+Tab)에 의해 캡처가 해제됨.
            // Win32 GetCursorPos로 최종 위치를 확인하여 삭제 여부 결정.
            DragAdornerWindow.GetCursorScreenPx(out int sx, out int sy);
            var localPt = PointFromScreen(new Point(sx, sy));
            if (!new Rect(0, 0, ActualWidth, ActualHeight).Contains(localPt))
                _insertIdx = -1;

            CloseAdorner();
            HideDropIndicator();
            ApplyDrop();
            ResetDragState();
        }
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
    //  End drag (normal path — applies drop then releases capture)
    // ══════════════════════════════════════════════════════════════════════
    private void EndDrag()
    {
        if (!_isDragging && _pendingDragBlock == null) return;

        _releasingCapture = true;
        CloseAdorner();
        HideDropIndicator();
        ApplyDrop();
        ResetDragState();
        ReleaseMouseCapture();
        _releasingCapture = false;
    }

    // ── Drop logic ────────────────────────────────────────────────────────
    private void ApplyDrop()
    {
        if (!_isDragging || _dragBlock == null || VM?.Blocks == null) return;

        if (_insertIdx < 0)
        {
            // 뷰 바깥에 드롭 → 블록 삭제
            VM.RemoveBlockCommand.Execute(_dragBlock);
        }
        else
        {
            // 뷰 안에 드롭 → 위치 이동
            int from = VM.Blocks.IndexOf(_dragBlock);
            int dest = _insertIdx > from ? _insertIdx - 1 : _insertIdx;
            if (from >= 0 && dest != from)
                VM.Blocks.Move(from, dest);
        }
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
