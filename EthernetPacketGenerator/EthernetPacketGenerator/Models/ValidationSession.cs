namespace EthernetPacketGenerator.Models;

public enum ValidationMatchMode
{
    Exact,
    Payload,
    DstMacAndPayload
}

public enum PacketValidationStatus
{
    Pending,
    Matched,
    Mismatch,
    Lost
}

public class ValidationConfig
{
    public int                 Count         { get; set; } = 1;
    public int                 TimeoutMs     { get; set; } = 2000;
    public int                 InterPacketMs { get; set; } = 10;
    public ValidationMatchMode MatchMode     { get; set; } = ValidationMatchMode.Exact;
    public string              RxFilter      { get; set; } = string.Empty;
}

public class PacketValidationRecord
{
    public int    Index           { get; init; }
    public byte[] SentBytes       { get; init; } = Array.Empty<byte>();
    public byte[] ReceivedBytes   { get; set;  } = Array.Empty<byte>();
    public PacketValidationStatus Status { get; set; } = PacketValidationStatus.Pending;
    public double LatencyMs       { get; set; }
    public string Note            { get; set; } = string.Empty;

    public int SentLength     => SentBytes.Length;
    public int ReceivedLength => ReceivedBytes.Length;

    public string StatusText => Status switch
    {
        PacketValidationStatus.Matched  => "✓  OK",
        PacketValidationStatus.Mismatch => "!  MISMATCH",
        PacketValidationStatus.Lost     => "✗  LOST",
        _                               => "···"
    };
}

public class ValidationSummary
{
    public int    TxCount       { get; set; }
    public int    RxCount       { get; set; }
    public int    MatchCount    { get; set; }
    public int    MismatchCount { get; set; }
    public int    LostCount     { get; set; }
    public double ElapsedMs     { get; set; }
    public double AvgLatencyMs  { get; set; }

    public double LossRate  => TxCount > 0 ? LostCount  * 100.0 / TxCount : 0.0;
    public double MatchRate => TxCount > 0 ? MatchCount * 100.0 / TxCount : 0.0;
}
