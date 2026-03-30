#include <ntddk.h>
#include "BlockEngine.h"

#define MAX_BLOCK_RULES 1024

BlockRuleV1 g_BlockRules[MAX_BLOCK_RULES];

void BlockEngine_Init() {
    RtlZeroMemory(g_BlockRules, sizeof(g_BlockRules));
}

NTSTATUS BlockEngine_AddRule(const BlockRuleV1* newRule) {
    if (!newRule) return STATUS_INVALID_PARAMETER;

    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);

    for (int i = 0; i < MAX_BLOCK_RULES; ++i) {
        BlockRuleV1* rule = &g_BlockRules[i];
        
        LONG active = InterlockedCompareExchange(&rule->is_active, 0, 0);
        bool expired = false;

        if (active == 1) {
            UINT64 expirationTime = rule->timestamp_added + (rule->ttl_ms * 10000ULL); 
            if ((UINT64)currentTime.QuadPart > expirationTime) {
                expired = true;
            }
        }

        if (active == 0 || expired) {
            if (InterlockedCompareExchange(&rule->is_active, 2, active) == active) {
                rule->ip_version = newRule->ip_version;
                rule->proto = newRule->proto;
                rule->src_port = newRule->src_port;
                rule->dst_port = newRule->dst_port;
                rule->ttl_ms = newRule->ttl_ms;
                RtlCopyMemory(rule->src_ip, newRule->src_ip, 16);
                RtlCopyMemory(rule->dst_ip, newRule->dst_ip, 16);
                
                KeQuerySystemTime(&currentTime);
                rule->timestamp_added = (UINT64)currentTime.QuadPart;

                KeMemoryBarrier();
                InterlockedExchange(&rule->is_active, 1);
                return STATUS_SUCCESS;
            }
        }
    }
    return STATUS_INSUFFICIENT_RESOURCES; 
}

bool ShouldBlockPacket(const PacketRecordV1* pkt) {
    if (!pkt) return false;

    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);

    for (int i = 0; i < MAX_BLOCK_RULES; ++i) {
        BlockRuleV1* rule = &g_BlockRules[i];

        // Volatile read prevents CPU bus stalling under massive network load
        if (*(volatile LONG*)&rule->is_active != 1) continue; 

        UINT64 expirationTime = rule->timestamp_added + (rule->ttl_ms * 10000ULL);
        if ((UINT64)currentTime.QuadPart > expirationTime) {
            InterlockedCompareExchange(&rule->is_active, 0, 1);
            continue;
        }

        if (rule->ip_version != 0 && rule->ip_version != pkt->ip_version) continue;
        if (rule->proto != 0 && rule->proto != pkt->proto) continue;
        if (rule->src_port != 0 && rule->src_port != pkt->src_port) continue;
        if (rule->dst_port != 0 && rule->dst_port != pkt->dst_port) continue;
        
        bool srcIpAny = true, dstIpAny = true;
        bool srcIpMatch = true, dstIpMatch = true;
        for (int j = 0; j < 16; ++j) {
            if (rule->src_ip[j] != 0) srcIpAny = false;
            if (rule->dst_ip[j] != 0) dstIpAny = false;
            if (rule->src_ip[j] != pkt->src_ip[j]) srcIpMatch = false;
            if (rule->dst_ip[j] != pkt->dst_ip[j]) dstIpMatch = false;
        }

        if (!srcIpAny && !srcIpMatch) continue;
        if (!dstIpAny && !dstIpMatch) continue;

        return true; 
    }
    return false;
}