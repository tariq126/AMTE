# Packet Record Documentation

This document provides a line-by-line detailed breakdown of the `PacketRecord.h` file within the SecAI Windows kernel driver. This header defines the exact memory blueprints forming the zero-copy shared memory buffer bridging the Kernel Network filter pipeline with the Python UI dashboard.

## Errors and Issues Solved

Synchronizing exact data layout bindings natively over a boundary between MSVC-compiled Kernel C++ and Python NumPy dictionaries yielded several deeply destructive architectural issues resolved directly inside this structure:

1. **"False Sharing" Cache-Line Contention:**
   * **Issue:** In early driver builds, the `head` and `tail` tracking variables existed next to each other in memory. Because modern CPU hardware synchronizes memory in 64-byte blocks (cache lines), every time Python updated the `tail` index to consume a packet, the CPU forcefully locked and flushed the entire memory line. The kernel writer concurrently trying to update `head` would stall, triggering a catastrophic performance crash.
   * **Solution:** Explicit 56-byte voids `pad1[56]` and `pad2[56]` were interwoven directly into `SharedMemoryHeader`. This enforces layout mechanics putting `head` and `tail` on entirely independent CPU cache lines, completely averting bus lockups on multicore processors.

2. **Memory Offset Mismatches & Data Tearing:**
   * **Issue:** C++ compilers inject invisible padding bytes into arrays to optimize hardware alignment. Because Python's `numpy` module was reading specific byte offsets, IP addresses were coming out as garbled hexadecimal gibberish because the arrays were out of sync.
   * **Solution:** The entire `SharedMemoryHeader` structure was entombed in `#pragma pack(1)` enforcing 1-byte alignment to disable implicit compiler padding. In conjunction with `pad3[40]`, the structure was manually inflated to perfectly align to exactly `192` bytes. A hard C++ `static_assert` validates the layout during compile time ensuring future edits don't break Python.

3. **Missing Vector Array Boundaries:**
   * **Issue:** When iterating large arrays of structs in C++, the compiler might start the next element unaligned, crashing or slowing down array parsing in Python.
   * **Solution:** Tagged the `PacketRecordV1` struct with `alignas(64)`. This guarantees that every single packet record allocates exactly 64 bytes of space matching exactly 1 standard CPU cache line, making copying exceptionally fast without layout overlap.

---

## Code Walkthrough: PacketRecord.h

```cpp
#pragma once
```
Instructs the C++ preprocessor compiler to only import this file's code definition a single time locally, avoiding duplicate struct definitions during linked compilation stages.

```cpp
#include <ntddk.h>
```
Natively connects the Microsoft Kernel Development Kit giving access to the specific data types required (e.g., `UINT32`, `UINT64`, `UINT8`) which are tightly monitored driver-safe standard sizes.

```cpp
/*
 * Memory Layout:
 * [SharedMemoryHeader] immediately followed by [PacketRecordV1 array]
 */
```
A top-level structural design brief representing how the 16MB mapped memory physically breaks down. 192 bytes up front for control telemetry, while the rest are consecutively glued payload records.

```cpp
#pragma pack(push, 1)
```
Locks the byte packing boundary tightly alongside 1-byte per instruction boundaries, telling the compiler explicitly to freeze its standard alignment padding behaviors for anything declared hereafter.

```cpp
typedef struct _SharedMemoryHeader {
    UINT32 schema_version;      // offset   0, 4 bytes
```
Establishes the structural versioning parameter at byte `0`. Crucial for long-term support as changing the struct layout would invalidate older Python dashboards; checking this allows graceful fallback operations.

```cpp
    UINT32 _pad0;               // offset   4, 4 bytes
```
Adds 4 bytes manually to push the active variables past the 8-byte mark preventing memory fragmentation.

```cpp
    volatile UINT64 head;       // offset   8, 8 bytes  (alignas(64) removed: ignored inside #pragma pack(1))
```
Generates an 8-byte pointer tracking where the kernel is inserting new packets. Market `volatile` signaling to the compiling algorithms that it is utterly illegal to cache this variable dynamically as parallel threads act on it unpredictably.

```cpp
    UINT8 pad1[56];             // offset  16, 56 bytes  -- cache-line isolation for head
```
Executes the fix correcting the catastrophic CPU "False Sharing" issue, explicitly carving out 56 bytes of pure 0's to forcefully detach the upcoming variable onto its own internal silicon cache block.

```cpp
    volatile UINT64 tail;       // offset  72, 8 bytes
    UINT8 pad2[56];             // offset  80, 56 bytes  -- cache-line isolation for tail
```
Deploys the counterpart reader variable dictating where Python currently sits. Like `head`, this structure is additionally padded downward preventing overlap backward.

```cpp
    volatile UINT64 capacity;   // offset 136, 8 bytes
```
Transmits the upper bounds limit natively calculated by the Kernel informing the dashboard mapping logic just how many elements the active array entails.

```cpp
    volatile UINT64 dropped_packets; // offset 144, 8 bytes
```
Hosts the atomical `InterlockedIncrement64` counter natively deployed when `head` collides with `tail`, communicating explicit overflow data. 

```cpp
    UINT8 pad3[40];             // offset 152, 40 bytes  -- pads struct to exactly 192 bytes
} SharedMemoryHeader;
#pragma pack(pop)
```
Executes the final mathematical boundary calculation filling empty bytes pushing the overall `struct` payload directly to the 192 boundary to enforce strict Python alignment before dynamically restoring original Microsoft compiler alignment parameters.

```cpp
// CRITICAL FIX 5.1 & 6.1: Python reads the packet array starting at byte 192.
// If this assert fires, sizeof() and Python's packet_array_offset=192 are out of sync.
static_assert(sizeof(SharedMemoryHeader) == 192, "SharedMemoryHeader MUST be exactly 192 bytes to match Python offset!");
```
Locks out broken compilations dynamically asserting the driver crashes out during the build phase natively if arbitrary C++ padding destroys the hardcoded NumPy synchronization constants.

```cpp
// Exactly 64 bytes = 1 CPU Cache Line
struct alignas(64) PacketRecordV1 {
```
Initiates the standard payload configuration. Forces the overall allocated boundaries directly mapping alongside explicit 64-byte structural spacing.

```cpp
    UINT64 mono_ts_ns;
```
Standard precision timestamp marking precisely when WFP delivered the event intercept down to the exact nanosecond integer.

```cpp
    UINT16 schema_version;
    UINT16 tcp_window;
    UINT32 if_index;
```
Tracks the version control map per execution payload (reduced to 16 bits to maintain alignment), captures the TCP window size via `tcp_window`, alongside tracking exactly what hardware Network Interface Controller (if_index) executed the transaction.

```cpp
    UINT32 captured_len;
    UINT32 wire_len;
```
Network diagnostic data verifying exactly how large the struct was mapped internally alongside detecting packet truncation (when the actual wire transmission drops bits vs the intercepted struct size).

```cpp
    UINT16 src_port;
    UINT16 dst_port;
    UINT8 direction;
```
Standardly maps routing destinations natively extracted during telemetry mapping while detecting if connection payloads are strictly outbound (`0`) or incoming (`1`).

```cpp
    UINT8 ip_version;
    UINT8 proto;
    UINT8 tcp_flags;
```
Isolates payload routing dynamics identifying network configurations (`IPv4` vs `IPv6`), specific transmission protocols (`TCP`/`UDP`), alongside explicit `TCP` flag markers.

```cpp
    UINT8 src_ip[16];
    UINT8 dst_ip[16];
};
```
Safely allocates uniform unmapped bounds covering IPv4 mapped boundaries up through the extended 16-byte IPv6 blocks maintaining alignment stability dynamically. 

```cpp
static_assert(sizeof(PacketRecordV1) == 64, "PacketRecordV1 must be exactly 64 bytes");
```
Final mathematical validation boundary asserting the struct compilation completes successfully aligned to the 64 byte constraint mapping correctly to the zero-copy array length offsets.
