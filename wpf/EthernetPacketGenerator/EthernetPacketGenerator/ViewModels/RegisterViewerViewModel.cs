using EthernetPacketGenerator.Services;
using EthernetPacketGenerator.ViewModels.RegisterViewer;

namespace EthernetPacketGenerator.ViewModels;

public class RegisterViewerViewModel : ViewModelBase
{
    private readonly RegisterService _reg;

    public SysControlViewModel  SysCtrl      { get; }
    public InterruptViewModel   Interrupt    { get; }
    public TimestampViewModel   Timestamp    { get; }
    public LedClockViewModel    LedClock     { get; }
    public TestDataViewModel    TestData     { get; }
    public FdbViewModel         Fdb          { get; }
    public CountViewerViewModel CountViewer  { get; }
    public MdioViewModel        Mdio         { get; }

    // ── BaseAddress (UI 바인딩용) ─────────────────────────────────────────
    public string BaseAddressHex
    {
        get => $"0x{_reg.BaseAddress:X8}";
        set
        {
            try
            {
                var hex = value.Replace("0x", "").Replace("0X", "").Trim();
                _reg.BaseAddress = Convert.ToUInt32(hex, 16);
                OnPropertyChanged();
                BaseAddressError = string.Empty;
            }
            catch
            {
                BaseAddressError = "잘못된 주소";
                OnPropertyChanged(nameof(BaseAddressError));
            }
        }
    }

    private string _baseAddressError = string.Empty;
    public string BaseAddressError
    {
        get => _baseAddressError;
        private set => SetProperty(ref _baseAddressError, value);
    }

    public RegisterViewerViewModel(SerialPortService serial)
    {
        _reg        = new RegisterService(serial);
        SysCtrl     = new SysControlViewModel(_reg);
        Interrupt   = new InterruptViewModel(_reg);
        Timestamp   = new TimestampViewModel(_reg);
        LedClock    = new LedClockViewModel(_reg);
        TestData    = new TestDataViewModel(_reg);
        Fdb         = new FdbViewModel(new FdbService(_reg));
        CountViewer = new CountViewerViewModel(serial);
        Mdio        = new MdioViewModel(new MdioService(_reg));
    }
}
