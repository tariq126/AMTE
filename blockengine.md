# BlockEngine Documentation

This document provides a line-by-line detailed explanation of the `BlockEngine` component in the SecAI Windows kernel driver. It covers both the header (`BlockEngine.h`) and implementation (`BlockEngine.cpp`) files. 

## Errors and Issues Solved

During the development and hardening of the BlockEngine, several critical errors and vulnerabilities were resolved:

1. **Memory Alignment and BSOD Prevention (`BlockRuleV1` structure)**
   * **Issue:** Data structure misalignment between C++ kernel space and Python user space was causing System Service Exceptions (BSOD). The compiler was adding implicit padding.
   * **Solution:** Added explicit padding (`_pad0` and `_pad1`) to `BlockRuleV1` and enforced 64-byte alignment boundaries. Used `#pragma pack(push, 1)` to manually layout memory cleanly, ensuring exact offsets for ctypes interoperability on the Python side.

2. **Race Conditions in Rule Table (`Interlocked` Operations)**
   * **Issue:** Updating rule slots from multiple cores simultaneously via user-mode IOCTL insertions or kernel automated expiry could lead to corrupted memory cells or rule truncation.
   * **Solution:** Adopted safe `InterlockedCompareExchange` primitives. Instead of blindly writing fields, the engine performs atomic state transitions on the `is_active` field (`0 -> 2` for claiming a slot, `2 -> 1` for publishing).

3. **Confused Deputy and Out-of-Bounds Queries**
   * **Issue:** User-mode tools could crash the driver by providing bad output capacities or mismatched request sizes during IOCTL transfers.
   * **Solution:** Enhanced defensive checks inside `BlockEngine_GetRules` ensuring `outCapacity` acts as a hard boundary, preventing buffer overflow vulnerabilities.

4. **Compiler Optimization Stalling (`volatile` reads)**
   * **Issue:** Heavy network loads caused the packet inspector loop to miss rules or stall because the compiler cached the value of `is_active` in a register.
   * **Solution:** Applied `*(volatile LONG*)&rule->is_active` to force a strict memory fetch on every iteration, preventing compiler hoisting while avoiding heavy CPU locks in the hot path.

5. **Safe Rule Deletion Constraints (`dstPort == 0`)**
   * **Issue:** Wildcard deletions posed a risk of unintentionally flushing routing tables or removing broad block rules if malformed IOCTLs were received.
   * **Solution:** Implemented a safeguard in `BlockEngine_RemoveRule` that immediately rejects `dstPort == 0`.

---

## Code Walkthrough: BlockEngine.h

```cpp
#pragma once
```
Guards against multiple inclusions of this header file during compilation, mitigating macro redefinition warnings or build loops.

```cpp
#define MAX_BLOCK_RULES 1024
```
Defines the maximum capacity of the driver's block rules array (1024 concurrent rules).

```cpp
#include <ntddk.h>
```
Includes the core Windows kernel driver API definitions required for types, memory routines, and standard macros.

```cpp
#ifndef NDIS61
#define NDIS61 1
#endif
#include <ndis.h>
#include <fwpsk.h>
```
Ensures NDIS version 6.1 context is set, then includes headers for network driver interfacing (`ndis.h`) and the Windows Filtering Platform (`fwpsk.h`).

```cpp
#include "../PacketRecord.h"
```
Includes the definition of `PacketRecordV1`, required for inspecting incoming packet fields.

```cpp
// Explicit padding and byte alignment for clarity
#pragma pack(push, 1)
```
Instructs the compiler to use 1-byte alignment for the structures that follow, eliminating implicit compiler padding.

```cpp
struct BlockRuleV1 {
```
Defines the memory structure for a firewall blocking rule.

```cpp
    UINT8 ip_version;
    UINT8 proto;
    UINT8 src_ip[16];
    UINT8 dst_ip[16];
    UINT16 src_port;
    UINT16 dst_port;
```
Defines standard network filtering parameters: IP version (IPv4/IPv6), Protocol (TCP/UDP), Source IP, Destination IP, Source Port, and Destination Port.

```cpp
    UINT8 _pad0[2]; // FIX: Pushes the next 64-bit int to a clean 8-byte boundary
```
Explicit 2-byte padding. Solves previous memory alignment crashes by ensuring the next 64-bit integer starts at a reliable offset.

```cpp
    UINT64 ttl_ms;
    UINT64 timestamp_added;
```
Stores the Time-To-Live in milliseconds and the exact system time when the rule was injected.

```cpp
    volatile LONG is_active;
```
A highly critical lock-free state variable (0=Empty, 1=Active, 2=Writing). Marked volatile in some usages to prevent CPU caching issues.

```cpp
    UINT8 _pad1[4]; // FIX: Pushes the total struct size to an even 64 bytes
};
#pragma pack(pop)
```
Adds 4 bytes of tail padding to reach exactly 64 bytes in size, followed by restoring default compiler alignment. 

```cpp
void BlockEngine_Init();
```
Clears and sets up the global `g_BlockRules` memory array, marking all default rules as inactive during driver initialization.

```cpp
NTSTATUS BlockEngine_AddRule(const BlockRuleV1* newRule);
```
Takes a pointer to a newly ingested rule from user-mode IOCTLs. Safely searches for an available array slot, or reclaims an expired one using RCU-style interlocking, without locking out packet processing threads. Returns an `NTSTATUS` code (e.g., `STATUS_SUCCESS` or `STATUS_INSUFFICIENT_RESOURCES`).

```cpp
bool ShouldBlockPacket(const PacketRecordV1* pkt);
```
The central evaluation hook called continuously by the WFP `ClassifyFn` callback. Rapidly loops over rules and returns `true` if the packet matches any active access-control structure, dictating that the connection should be dropped.

```cpp
ULONG BlockEngine_GetRules(_Out_writes_(outCapacity) BlockRuleV1* outBuffer, _In_ ULONG outCapacity);
```
Allows external diagnostic systems (e.g., the Python UI dashboard) to safely pull a snapshot of all active firewalls rules. It executes non-blocking read barriers to prevent crashes if a rule is expiring or changing while being read. Returns the total count of valid rules deposited into `outBuffer`.

```cpp
NTSTATUS BlockEngine_RemoveRule(_In_ UINT16 dstPort);
```
Targeted API enabling dynamic and thread-safe rule deactivations. It scans for the given destination port and attempts to atomically flick the rule to an inactive state. Returns `STATUS_SUCCESS` if it destroyed a rule, or `STATUS_NOT_FOUND` if no match existed.

---

## Code Walkthrough: BlockEngine.cpp

```cpp
#include <ntddk.h>
#include "BlockEngine.h"
```
Includes dependencies and the header definitions.

```cpp
BlockRuleV1 g_BlockRules[MAX_BLOCK_RULES];
```
Allocates a global kernel non-paged memory array forming the core table of rules.

```cpp
void BlockEngine_Init() {
    RtlZeroMemory(g_BlockRules, sizeof(g_BlockRules));
}
```
Initializes the engine by wiping the entire rule array to zeroes, meaning all slots start as `is_active == 0`.

```cpp
NTSTATUS BlockEngine_AddRule(const BlockRuleV1* newRule) {
    if (!newRule) return STATUS_INVALID_PARAMETER;
```
Validates that a rule pointer was actually provided.

```cpp
    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);
```
Fetches the current canonical system time for TTL calculations.

```cpp
    for (int i = 0; i < MAX_BLOCK_RULES; ++i) {
        BlockRuleV1* rule = &g_BlockRules[i];
```
Iterates over every slot in the global rule array.

```cpp
        LONG active = InterlockedCompareExchange(&rule->is_active, 0, 0);
        bool expired = false;
```
Safely peeks at the `is_active` state without altering it. Initializes `expired` to false.

```cpp
        if (active == 1) {
            UINT64 expirationTime = rule->timestamp_added + (rule->ttl_ms * 10000ULL); 
            if ((UINT64)currentTime.QuadPart > expirationTime) {
                expired = true;
            }
        }
```
If the slot is currently holding an active rule, it computes when the rule should die (multiplying ttl_ms by 10,000 to convert to Windows 100-nanosecond ticks). If the current time is past expiration, it flags the slot as expired.

```cpp
        if (active == 0 || expired) {
```
The algorithm looks for an empty slot or a slot holding a dead rule.

```cpp
            if (InterlockedCompareExchange(&rule->is_active, 2, active) == active) {
```
Atomic "Compare and Swap". If the slot state is still what we thought it was (`active`), it locks it by writing `2` (meaning 'currently writing').

```cpp
                rule->ip_version = newRule->ip_version;
                rule->proto = newRule->proto;
                rule->src_port = newRule->src_port;
                rule->dst_port = newRule->dst_port;
                rule->ttl_ms = newRule->ttl_ms;
                RtlCopyMemory(rule->src_ip, newRule->src_ip, 16);
                RtlCopyMemory(rule->dst_ip, newRule->dst_ip, 16);
```
Performs the actual memory copy of the filtering parameters inside our reserved slot.

```cpp
                KeQuerySystemTime(&currentTime);
                rule->timestamp_added = (UINT64)currentTime.QuadPart;
```
Records the final system time stamp indicating exactly when insertion finished.

```cpp
                KeMemoryBarrier();
                InterlockedExchange(&rule->is_active, 1);
                return STATUS_SUCCESS;
            }
        }
    }
    return STATUS_INSUFFICIENT_RESOURCES; 
}
```
Executes a memory barrier to force all CPU cores to synchronize data writes before setting `is_active` to `1` (publishing it live). If the loop exhausts all slots without finding space, it returns an error.

```cpp
bool ShouldBlockPacket(const PacketRecordV1* pkt) {
    if (!pkt) return false;
    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);
```
The high-performance classification hot-path. Checks the packet payload and grabs system time.

```cpp
    for (int i = 0; i < MAX_BLOCK_RULES; ++i) {
        BlockRuleV1* rule = &g_BlockRules[i];
```
Loops through the firewall table.

```cpp
        // Volatile read prevents CPU bus stalling under massive network load
        if (*(volatile LONG*)&rule->is_active != 1) continue; 
```
Checks if the rule is live. The volatile cast guarantees the CPU reads physical RAM rather than an expired cache register.

```cpp
        UINT64 expirationTime = rule->timestamp_added + (rule->ttl_ms * 10000ULL);
        if ((UINT64)currentTime.QuadPart > expirationTime) {
            InterlockedCompareExchange(&rule->is_active, 0, 1);
            continue;
        }
```
Checks if the rule has expired on the fly. If so, it aggressively disables it before continuing the loop.

```cpp
        if (rule->ip_version != 0 && rule->ip_version != pkt->ip_version) continue;
        if (rule->proto != 0 && rule->proto != pkt->proto) continue;
        if (rule->src_port != 0 && rule->src_port != pkt->src_port) continue;
        if (rule->dst_port != 0 && rule->dst_port != pkt->dst_port) continue;
```
Scalar field matching. If the rule specifies a parameter (non-zero) and it mismatches the packet, the packet goes to the next rule.

```cpp
        bool srcIpAny = true, dstIpAny = true;
        bool srcIpMatch = true, dstIpMatch = true;
        for (int j = 0; j < 16; ++j) {
            if (rule->src_ip[j] != 0) srcIpAny = false;
            if (rule->dst_ip[j] != 0) dstIpAny = false;
            if (rule->src_ip[j] != pkt->src_ip[j]) srcIpMatch = false;
            if (rule->dst_ip[j] != pkt->dst_ip[j]) dstIpMatch = false;
        }
```
Byte-by-byte comparison of IPs. It traces whether the rule has a generic IP ("Any") and whether the specific IPs match.

```cpp
        if (!srcIpAny && !srcIpMatch) continue;
        if (!dstIpAny && !dstIpMatch) continue;
        return true; 
    }
    return false;
}
```
Final policy check. If the IP rules apply and match, the function returns `true` (packet blocked). If it survives all rules, it returns `false` (packet permitted).

```cpp
ULONG BlockEngine_GetRules(
    _Out_writes_(outCapacity) BlockRuleV1* outBuffer,
    _In_ ULONG outCapacity)
{
    if (!outBuffer || outCapacity == 0) return 0;
```
Exports the live rules to user-space. Begins by validating the user buffer size.

```cpp
    ULONG count = 0;
    for (int i = 0; i < MAX_BLOCK_RULES && count < outCapacity; ++i) {
        BlockRuleV1* src = &g_BlockRules[i];
```
Loops until it fills the requested capacity or runs out of slots.

```cpp
        LONG active = *(volatile LONG*)&src->is_active;
        if (active != 1) continue;
```
Again uses volatile reading to find strictly live rules.

```cpp
        LARGE_INTEGER now;
        KeQuerySystemTime(&now);
        UINT64 expirationTime = src->timestamp_added + (src->ttl_ms * 10000ULL);
        if ((UINT64)now.QuadPart > expirationTime) {
            InterlockedCompareExchange(&src->is_active, 0, 1);
            continue;
        }
```
Clears and skips implicitly dead rules that haven't been swept away yet.

```cpp
        RtlCopyMemory(&outBuffer[count], src, sizeof(BlockRuleV1));
        ++count;
    }
    return count;
}
```
Copies the clean rule into the output buffer array and pushes the counter. Then it returns the total number of rules exported.

```cpp
NTSTATUS BlockEngine_RemoveRule(_In_ UINT16 dstPort)
{
    if (dstPort == 0) return STATUS_INVALID_PARAMETER;
```
Targeted rule removal mechanism. Refuses port 0 to prevent unintentional catastrophic wipe of "any port" rules.

```cpp
    for (int i = 0; i < MAX_BLOCK_RULES; ++i) {
        BlockRuleV1* rule = &g_BlockRules[i];
        LONG active = *(volatile LONG*)&rule->is_active;
        if (active != 1) continue;
        if (rule->dst_port != dstPort) continue;
```
Finds a matching live rule that has the specific Destination Port.

```cpp
        if (InterlockedCompareExchange(&rule->is_active, 0, 1) == 1) {
            KeMemoryBarrier();
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}
```
Attempts one final race-safe "Compare and Swap" to transition the rule from Active (`1`) to Empty (`0`). Follows up with a `KeMemoryBarrier` constraint to serialize cache visibility across all processor cores. If no matching rule was deactivated, returns `STATUS_NOT_FOUND`.
