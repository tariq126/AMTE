#pragma once
#include <ntddk.h>

/*
 * Memory Layout:
 * [SharedMemoryHeader] immediately followed by [PacketRecordV1 array]
 */

struct alignas(64) SharedMemoryHeader {
    UINT32 schema_version;
    UINT32 _pad0; // Align to 8
    
    volatile UINT64 head;
    char pad1[56]; // Prevent false sharing

    volatile UINT64 tail;
    char pad2[56]; // Prevent false sharing

    UINT64 capacity;
    UINT64 dropped_packets;
};

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
