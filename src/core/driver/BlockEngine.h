#pragma once
#include <ntddk.h>
#ifndef NDIS61
#define NDIS61 1
#endif
#include <ndis.h>
#include <fwpsk.h>
#include "../PacketRecord.h"

// Explicit padding and byte alignment for clarity
struct BlockRuleV1 {
    UINT8  ip_version;
    UINT8  proto;
    UINT8  src_ip[16];
    UINT8  dst_ip[16];
    UINT16 src_port;
    UINT16 dst_port;
    UINT64 ttl_ms;
    UINT64 timestamp_added;
    
    // Lock-free Management state
    // 0 = Empty, 1 = Active, 2 = Writing (Reserved)
    volatile LONG is_active;
};

// Initializes the Block Engine table
void BlockEngine_Init();

// Handles User-Mode IOCTL insertions safely using RCU-style interlocking
NTSTATUS BlockEngine_AddRule(const BlockRuleV1* newRule);

// ClassifyFn evaluation hook
bool ShouldBlockPacket(const PacketRecordV1* pkt);
