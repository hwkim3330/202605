using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using EthernetPacketGenerator.Models;

namespace EthernetPacketGenerator.Services;

public static class TestCaseSerializer
{
    private static readonly JsonSerializerOptions Opts = new() { WriteIndented = true };

    // ── Snapshot: SequenceItem list → DTO list ────────────────────────────────
    public static List<SequenceItemDto> TakeSnapshot(IEnumerable<SequenceItem> items)
    {
        var dtos = new List<SequenceItemDto>();
        foreach (var item in items)
        {
            if (item.Kind == SequenceItemKind.Packet && item.Packet != null)
            {
                dtos.Add(new SequenceItemDto
                {
                    Kind       = "Packet",
                    IsChecked  = item.IsChecked,
                    PacketName = item.Packet.Name,
                    Blocks     = item.Packet.Blocks.Select(b => new SequenceItemDto.BlockDto
                    {
                        Type  = b.Type.ToString(),
                        Bytes = Convert.ToBase64String(b.Bytes)
                    }).ToList()
                });
            }
            else if (item.Kind == SequenceItemKind.Event && item.Event != null)
            {
                var ev = item.Event;
                dtos.Add(new SequenceItemDto
                {
                    Kind       = "Event",
                    EventType  = ev.EventType.ToString(),
                    DelayMs    = ev.DelayMs,
                    Address    = $"0x{ev.Address:X8}",
                    Value      = $"0x{ev.Value:X8}",
                    Mask       = $"0x{ev.Mask:X8}",
                    Expected   = $"0x{ev.Expected:X8}",
                    TimeoutMs  = ev.TimeoutMs,
                    MacAddress = ev.MacAddress,
                    VlanValid  = ev.VlanValid,
                    VlanId     = ev.VlanId,
                    Port       = ev.Port,
                    Bucket     = ev.Bucket,
                    SlotBitmap = ev.SlotBitmap
                });
            }
        }
        return dtos;
    }

    // ── Restore: DTO list → SequenceItem list ────────────────────────────────
    public static List<SequenceItem> RestoreSequence(List<SequenceItemDto> dtos)
    {
        var items = new List<SequenceItem>();
        foreach (var dto in dtos)
        {
            if (dto.Kind == "Packet")
            {
                var packet = new PacketItem { Name = dto.PacketName ?? "Packet" };
                foreach (var bd in dto.Blocks ?? new())
                {
                    if (!Enum.TryParse<ProtocolType>(bd.Type, out var type)) continue;
                    var block = PacketItem.CreateBlock(type);
                    block.ImportBytes(Convert.FromBase64String(bd.Bytes), 0);
                    block.PropertyChanged += (_, _) => packet.Invalidate();
                    packet.Blocks.Add(block);
                }
                var si = new SequenceItem(packet);
                si.IsChecked = dto.IsChecked;
                items.Add(si);
            }
            else if (dto.Kind == "Event")
            {
                if (!Enum.TryParse<SequenceEventType>(dto.EventType ?? "", out var evType)) continue;
                var ev = new SequenceEvent
                {
                    EventType  = evType,
                    DelayMs    = dto.DelayMs,
                    Address    = ParseHex(dto.Address),
                    Value      = ParseHex(dto.Value),
                    Mask       = ParseHex(dto.Mask),
                    Expected   = ParseHex(dto.Expected),
                    TimeoutMs  = dto.TimeoutMs,
                    MacAddress = dto.MacAddress,
                    VlanValid  = dto.VlanValid,
                    VlanId     = dto.VlanId,
                    Port       = dto.Port,
                    Bucket     = dto.Bucket,
                    SlotBitmap = dto.SlotBitmap
                };
                items.Add(new SequenceItem(ev));
            }
        }
        return items;
    }

    // ── File I/O (그룹 컬렉션) ───────────────────────────────────────────────
    public static void SaveToFile(IEnumerable<TestCaseGroup> groups, string path)
    {
        var dtos = groups.Select(g => new GroupFileDto
        {
            GroupName = g.Name,
            TestCases = g.TestCases.Select(tc => new TcFileDto
            {
                Name  = tc.Name,
                Items = tc.Items
            }).ToList()
        }).ToList();
        File.WriteAllText(path, JsonSerializer.Serialize(dtos, Opts));
    }

    public static List<TestCaseGroup> LoadFromFile(string path)
    {
        var dtos = JsonSerializer.Deserialize<List<GroupFileDto>>(File.ReadAllText(path), Opts) ?? new();
        return dtos.Select(dto =>
        {
            var group = new TestCaseGroup { Name = dto.GroupName };
            foreach (var tc in dto.TestCases)
                group.TestCases.Add(new TestCaseEntry { Name = tc.Name, Items = tc.Items });
            return group;
        }).ToList();
    }

    private static uint ParseHex(string s)
    {
        var clean = s.Replace("0x", "").Replace("0X", "").Replace("_", "").Trim();
        return uint.TryParse(clean, NumberStyles.HexNumber, null, out var v) ? v : 0;
    }

    private class GroupFileDto
    {
        [JsonPropertyName("groupName")] public string GroupName { get; set; } = "";
        [JsonPropertyName("testCases")] public List<TcFileDto> TestCases { get; set; } = new();
    }

    private class TcFileDto
    {
        [JsonPropertyName("name")]  public string Name  { get; set; } = "";
        [JsonPropertyName("items")] public List<SequenceItemDto> Items { get; set; } = new();
    }
}
