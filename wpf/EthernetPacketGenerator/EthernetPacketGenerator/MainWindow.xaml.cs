using System.Windows;
using EthernetPacketGenerator.Models;
using EthernetPacketGenerator.ViewModels;

namespace EthernetPacketGenerator;

public partial class MainWindow : Window
{
    private MainViewModel ViewModel => (MainViewModel)DataContext;

    public MainWindow()
    {
        InitializeComponent();
        Loaded  += OnLoaded;
        Closing += (_, _) => ViewModel.TestCaseMgrVM.AutoSave();
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        BlockBuilder.SelectedBlockChanged += (_, block) =>
            ViewModel.SelectedBlock = block;

        // 팔레트 클릭 시 끝에 블록 추가 (드래그 불가 환경 대비)
        ProtocolPalette.ProtocolAddRequested += (_, type) =>
            ViewModel.BlockBuilderVM.InsertBlock(type, int.MaxValue);
    }

    private void MenuExit_Click(object sender, RoutedEventArgs e) => Close();
}
