#pragma once
#include <ntddk.h>

/*
 * Memory Layout:
 * [SharedMemoryHeader] immediately followed by [PacketRecordV1 array]
 */

#pragma pack(push, 1)
typedef struct _SharedMemoryHeader {
    UINT32 schema_version;
    UINT32 _pad0;
    volatile alignas(64) UINT64 head;
    UINT8 pad1[56];
    volatile alignas(64) UINT64 tail;
    UINT8 pad2[56];
    volatile UINT64 capacity;
    volatile UINT64 dropped_packets;
    UINT8 pad3[40]; // FIX: Pads the struct to exactly 192 bytes (64 * 3) to prevent BSOD
} SharedMemoryHeader;
#pragma pack(pop)

// Exactly 64 bytes = 1 CPU Cache Line
struct alignas(64) PacketRecordV1 {
    UINT64 mono_ts_ns;
    UINT32 schema_version;
    UINT32 if_index;
    UINT32 captured_len;
    UINT32 wire_len;
    UINT16 src_port;
    UINT16 dst_port;
    UINT8 direction;
    UINT8 ip_version;
    UINT8 proto;
    UINT8 tcp_flags;
    UINT8 src_ip[16];
    UINT8 dst_ip[16];
};

static_assert(sizeof(PacketRecordV1) == 64, "PacketRecordV1 must be exactly 64 bytes");
