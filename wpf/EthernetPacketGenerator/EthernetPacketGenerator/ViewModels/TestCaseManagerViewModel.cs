using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Windows.Input;
using EthernetPacketGenerator.Commands;
using EthernetPacketGenerator.Models;
using EthernetPacketGenerator.Services;
using Microsoft.Win32;

namespace EthernetPacketGenerator.ViewModels;

public class TestCaseManagerViewModel : ViewModelBase
{
    private readonly PacketListViewModel _packetList;
    private TestCaseEntry? _selectedTc;
    private TestCaseGroup? _selectedGroup;
    private string _status = "";

    private static readonly string AutoSavePath = Path.Combine(
        AppContext.BaseDirectory, "test_cases.tcs");

    public ObservableCollection<TestCaseGroup> Groups { get; } = new();

    public TestCaseEntry? SelectedTc => _selectedTc;

    public string Status
    {
        get => _status;
        set => SetProperty(ref _status, value);
    }

    // ── Commands ──────────────────────────────────────────────────────────────
    public ICommand AddGroupCommand     { get; }
    public ICommand AddTcToGroupCommand { get; }              // param: TestCaseGroup
    public ICommand ToggleGroupCommand  { get; }              // param: TestCaseGroup
    public ICommand SelectTcCommand     { get; }              // param: TestCaseEntry
    public ICommand DeleteTcCommand     { get; }              // param: TestCaseEntry  (우클릭 메뉴)
    public ICommand DeleteGroupCommand  { get; }              // param: TestCaseGroup  (우클릭 메뉴)
    public ICommand DeleteCommand       { get; }              // 툴바 [−] 버튼용
    public ICommand SaveTcCommand       { get; }
    public ICommand SaveFileCommand     { get; }
    public ICommand LoadFileCommand     { get; }

    public TestCaseManagerViewModel(PacketListViewModel packetList)
    {
        _packetList = packetList;

        AddGroupCommand     = new RelayCommand(AddGroup);
        AddTcToGroupCommand = new RelayCommand<TestCaseGroup>(AddTcToGroup);
        ToggleGroupCommand  = new RelayCommand<TestCaseGroup>(g => { if (g != null) g.IsExpanded = !g.IsExpanded; });
        SelectTcCommand     = new RelayCommand<TestCaseEntry>(SelectTc);
        DeleteTcCommand     = new RelayCommand<TestCaseEntry>(DeleteTc);
        DeleteGroupCommand  = new RelayCommand<TestCaseGroup>(DeleteGroup);
        DeleteCommand       = new RelayCommand(Delete, CanDelete);
        SaveTcCommand       = new RelayCommand(SaveTc,   () => _selectedTc != null);
        SaveFileCommand     = new RelayCommand(SaveToFile, () => Groups.Any());
        LoadFileCommand     = new RelayCommand(LoadFromFile);

        AutoLoad();
    }

    // ── 그룹 추가 ────────────────────────────────────────────────────────────
    private void AddGroup()
    {
        var group = new TestCaseGroup { Name = $"Group{Groups.Count + 1}" };
        Groups.Add(group);
        _selectedGroup = group;
        CommandManager.InvalidateRequerySuggested();
    }

    // ── TC 추가 (그룹 내) ────────────────────────────────────────────────────
    private void AddTcToGroup(TestCaseGroup? group)
    {
        if (group == null) return;
        _selectedGroup = group;
        group.IsExpanded = true;

        var tc = new TestCaseEntry { Name = $"TC{group.TestCases.Count + 1}" };
        group.TestCases.Add(tc);
        SelectTc(tc);
    }

    // ── TC 선택 → PACKET LIST 로드 ───────────────────────────────────────────
    private void SelectTc(TestCaseEntry? tc)
    {
        if (_selectedTc != null) _selectedTc.IsSelected = false;
        _selectedTc = tc;
        if (tc != null)
        {
            tc.IsSelected = true;
            _selectedGroup = FindGroupOf(tc) ?? _selectedGroup;
            var items = TestCaseSerializer.RestoreSequence(tc.Items);
            _packetList.LoadSequence(items);
            Status = $"{tc.Name}  로드됨";
        }
        CommandManager.InvalidateRequerySuggested();
    }

    // ── 우클릭 메뉴용 삭제 ────────────────────────────────────────────────────
    private void DeleteTc(TestCaseEntry? tc)
    {
        if (tc == null) return;
        var group = FindGroupOf(tc);
        if (tc == _selectedTc)
        {
            _selectedTc.IsSelected = false;
            _selectedTc = null;
        }
        group?.TestCases.Remove(tc);
        Status = "삭제됨";
        CommandManager.InvalidateRequerySuggested();
    }

    private void DeleteGroup(TestCaseGroup? group)
    {
        if (group == null) return;
        if (group == _selectedGroup) _selectedGroup = null;
        if (_selectedTc != null && group.TestCases.Contains(_selectedTc))
        {
            _selectedTc.IsSelected = false;
            _selectedTc = null;
        }
        Groups.Remove(group);
        Status = "그룹 삭제됨";
        CommandManager.InvalidateRequerySuggested();
    }

    // ── 삭제: TC 선택 시 TC, 아니면 마지막 활성 그룹 ────────────────────────
    private void Delete()
    {
        if (_selectedTc != null)
        {
            var group = FindGroupOf(_selectedTc);
            _selectedTc.IsSelected = false;
            group?.TestCases.Remove(_selectedTc);
            _selectedTc = null;
            Status = "삭제됨";
        }
        else if (_selectedGroup != null)
        {
            Groups.Remove(_selectedGroup);
            _selectedGroup = null;
            Status = "그룹 삭제됨";
        }
        CommandManager.InvalidateRequerySuggested();
    }

    private bool CanDelete() => _selectedTc != null || _selectedGroup != null;

    // ── 현재 PACKET LIST → 선택된 TC에 저장 ─────────────────────────────────
    private void SaveTc()
    {
        if (_selectedTc == null) return;
        _selectedTc.Items = TestCaseSerializer.TakeSnapshot(_packetList.Sequence);
        Status = $"저장됨  {DateTime.Now:HH:mm:ss}";
    }

    // ── 파일 저장/로드 ────────────────────────────────────────────────────────
    private void SaveToFile()
    {
        var dlg = new SaveFileDialog
        {
            Filter = "Test Case Suite (*.tcs)|*.tcs|All Files (*.*)|*.*",
            DefaultExt = "tcs"
        };
        if (dlg.ShowDialog() != true) return;
        try   { TestCaseSerializer.SaveToFile(Groups, dlg.FileName); Status = "파일 저장 완료"; }
        catch (Exception ex) { Status = $"저장 실패: {ex.Message}"; }
    }

    private void LoadFromFile()
    {
        var dlg = new OpenFileDialog
        {
            Filter = "Test Case Suite (*.tcs)|*.tcs|All Files (*.*)|*.*"
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            ApplyLoadedGroups(TestCaseSerializer.LoadFromFile(dlg.FileName));
            Status = $"로드 완료 ({Groups.Count}개 그룹)";
        }
        catch (Exception ex) { Status = $"로드 실패: {ex.Message}"; }
    }

    // ── 자동 저장/로드 ────────────────────────────────────────────────────────
    public void AutoSave()
    {
        try
        {
            TestCaseSerializer.SaveToFile(Groups, AutoSavePath);
        }
        catch { }
    }

    private void AutoLoad()
    {
        if (!File.Exists(AutoSavePath)) return;
        try   { ApplyLoadedGroups(TestCaseSerializer.LoadFromFile(AutoSavePath)); }
        catch { }
    }

    private void ApplyLoadedGroups(System.Collections.Generic.List<TestCaseGroup> loaded)
    {
        Groups.Clear();
        foreach (var g in loaded) Groups.Add(g);
        var first = Groups.SelectMany(g => g.TestCases).FirstOrDefault();
        if (first != null) SelectTc(first);
    }

    // ── 헬퍼 ────────────────────────────────────────────────────────────────
    private TestCaseGroup? FindGroupOf(TestCaseEntry tc) =>
        Groups.FirstOrDefault(g => g.TestCases.Contains(tc));
}
