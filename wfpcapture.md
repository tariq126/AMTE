# WfpCapture Documentation

This document provides a line-by-line detailed breakdown of the `WfpCapture.cpp` module in the SecAI Windows kernel driver. This file serves as the core networking engine integrating deep within the Windows Filtering Platform (WFP), handling packet interception, telemetry extraction, and active connection blocking.

## Errors and Issues Solved

This specific module handles direct interaction with the harsh environment of Windows networking stacks. As such, multiple severe vulnerabilities and system-crashing bugs were rectified:

1. **TERMINATING Action BSOD (`FWP_ACTION_PERMIT` Fix):**
   * **Issue:** Initially, the filter was configured for `INSPECTION`, which meant it could only watch packets, not block them. When we upgraded the action type to `FWP_ACTION_CALLOUT_TERMINATING`, the driver immediately began blue screening (BSOD). This occurred because if a terminating filter decides *not* to block a packet, it cannot just return; it implicitly causes a system fault unless explicitly told to permit it.
   * **Solution:** We explicitly enforced `classifyOut->actionType = FWP_ACTION_PERMIT` at the very top of `ClassifyFn`. Crucially, we left the `FWPS_RIGHT_ACTION_WRITE` flag intact allowing lower-priority firewalls (like Windows Defender) to override our permit and block the packet if they deemed it malicious.

2. **Metadata Extraction Out-Of-Order:**
   * **Issue:** Driver telemetry was reporting all packets had `0` for TCP Flags, and no IPs or Ports were being logged. The old logic was checking if `pkt.proto == 6` (TCP) to gather flags *before* it actually parsed the WFP metadata block to populate `pkt.proto`.
   * **Solution:** Code was completely reordered to establish Layer ID definitions first, pulling out correct IPs, Ports, and `ip_version`/`proto` from `inFixedValues`. Then, the TCP segment inspects the newly populated protocol successfully.

3. **Interlocked 64-Bit Alignment Faults:**
   * **Issue:** While x64 systems handled it fine, using `InterlockedCompareExchange64` to calculate batch timings natively crashed 32-bit (x86) and ARM kernels with an Alignment Fault.
   * **Solution:** Forced the compiler to align the `g_LastBatchRunTime` structure natively to the hardware by assigning `__declspec(align(8))`.

4. **BFE Registration Crash (NULL Names):**
   * **Issue:** Registering filter rules with `FwpmFilterAdd0` failed or crashed the Base Filtering Engine (BFE) entirely.
   * **Solution:** While MS docs say `displayData.name` is optional, feeding a `NULL` name reliably crashed our stack. We explicitly padded `(wchar_t*)L"SecAI_Filter_...` on all inbound/outbound filter structs.

---

## Code Walkthrough: WfpCapture.cpp

```cpp
#include <ntddk.h>
#include <wdf.h>
...
#include <fwpsk.h>
#include <fwpmk.h>
```
Standard header block. Imports the core driver tools and specifically targets the Windows Filtering Platform Kernel Engine (`fwpsk.h`, `fwpmk.h`).

```cpp
#pragma comment(lib, "ndis.lib")
#pragma comment(lib, "fwpkclnt.lib")
```
Automatically links the Network Driver Interface Specification and the WFP Kernel Client libraries, preventing "Unresolved External Symbol" linking errors during compile.

```cpp
#pragma warning(push)
#pragma warning(disable: 4201) 
```
Temporarily disables a strict compiler warning regarding "nameless struct/union," which Microsoft's own header files trigger natively.

```cpp
volatile LONG g_BatchCount = 0;
// Must be 8-byte aligned for InterlockedExchange64 -- alignment fault = BSOD
__declspec(align(8)) LARGE_INTEGER g_LastBatchRunTime = {0};
```
These globals limit performance hits by batching packet notifications. Instead of signaling Python for *every* individual packet (which exhausts CPU), we track count and time. `__declspec(align(8))` fixes the hardware alignment crash.

```cpp
EXTERN_C const GUID DECLSPEC_SELECTANY SEC_AI_CALLOUT_IN_V4  = { 0x11111111...
```
Unique identifiers defining our specific intercept routes into the Windows network stack.

```cpp
#pragma alloc_text (NONPAGE, ClassifyFn)
```
Forces the classification function directly into Non-Paged pool memory. Because WFP can invoke this function wildly fast at `DISPATCH_LEVEL` IRQL, if it resided in pagable memory, it would instantly trigger a SYSTEM_SERVICE_EXCEPTION BSOD.

```cpp
UINT32 GetTcpMss(PNET_BUFFER_LIST nbl) {
    ...
```
Helper function. Looks past generic headers to dig out the TCP Maximum Segment Size out of the hardware Offload metrics. 

```cpp
void NTAPI ClassifyFn( ... ) {
```
The grand central station. The base engine fires this callback completely asynchronously every time a packet arrives or leaves the NIC.

```cpp
    bool canWriteAction = false;
    if (classifyOut && (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)) {
        canWriteAction = true;
        classifyOut->actionType = FWP_ACTION_PERMIT; 
    }
```
**Critical Patch Zone:** Begins by guaranteeing that if we officially hold the right to dictate what happens to this packet, we set it to PERMIT by default.

```cpp
    PNET_BUFFER_LIST nbl = (PNET_BUFFER_LIST)layerData;
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
```
Unpacks the abstract Network Descriptor structure from WFP into raw buffer pointers.

```cpp
    PacketRecordV1 pkt = {0};
    LARGE_INTEGER ts;
    KeQuerySystemTime(&ts);
    pkt.mono_ts_ns = ts.QuadPart * 100; 
```
Begins constructing the telemetry payload for Python. Captures execution nanoseconds.

```cpp
    if (inFixedValues->layerId == FWPS_LAYER_INBOUND_TRANSPORT_V4) {
        pkt.ip_version = 4; pkt.direction = 1;
        pkt.proto   = inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_PROTOCOL].value.uint8;
        ...
```
Decodes the contextual layer WFP fed us. If it is IPv4 inbound, we cleanly map IP versions, remote/local ports, and protocols. 

```cpp
        UINT32 srcIp = RtlUlongByteSwap(inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V4_IP_REMOTE_ADDRESS].value.uint32);
```
Little-Endian vs Big-Endian fix. Microsoft delivers IPv4 endpoints natively as Little Endian, which Python's network modules reject. `RtlUlongByteSwap` instantly pivots it to classical network-byte (Big-Endian) order.

```cpp
        // IPv6 addresses from WFP are already in network-byte order
        RtlCopyMemory(pkt.src_ip, inFixedValues->incomingValue[FWPS_FIELD_INBOUND_TRANSPORT_V6_IP_REMOTE_ADDRESS].value.byteArray16->byteArray16, 16);
```
In sharp contrast to IPv4, Microsoft structures IPv6 addresses already correctly byte-aligned, so a raw memory chunk copy directly to `pkt.src_ip` suffices.

```cpp
    pkt.tcp_flags = 0;
    if (packetLength >= 20 && pkt.proto == 6) { // 6 = IPPROTO_TCP
        UCHAR safeBuffer[20];
        PVOID pData = NdisGetDataBuffer(nb, sizeof(safeBuffer), safeBuffer, 1, 0);
```
Uses the now-stablized `pkt.proto` to confirm TCP presence. Checks length safety, utilizes Ndis to extract the header, and reads byte `13` (where TCP Flags like SYN/ACK reside).

```cpp
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_RingBufferLock, &oldIrql);
    RingBuffer_Push(header, records, &pkt);
    KeReleaseSpinLock(&g_RingBufferLock, oldIrql);
```
Halt interrupts! Since this function is simultaneously executing across every CPU core on the machine for parallel network connections, we acquire a SpinLock locking memory access, push the structured packet onto the ring buffer, and instantly unlock.

```cpp
    if (ShouldBlockPacket(&pkt)) {
        if (canWriteAction) {
            classifyOut->actionType = FWP_ACTION_BLOCK;
            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        }
    }
```
Fires the rule lookup inside `BlockEngine.cpp`. If a match returns `true`, and we have writable permissions, we violently swap the routing behavior from `PERMIT` to `BLOCK`. Additionally, we clear `FWPS_RIGHT_ACTION_WRITE`, telling Windows, "We blocked this, DO NOT let any other system change this answer."

```cpp
    LONGLONG lastRunTime = InterlockedCompareExchange64((volatile LONGLONG*)&g_LastBatchRunTime.QuadPart, 0LL, 0LL);
    LONGLONG elapsed = currentTime.QuadPart - lastRunTime;

    if (currentCount >= 1024 || elapsed >= 50000) {
        if (g_PacketEvent) KeSetEvent(g_PacketEvent, 0, FALSE);
    }
```
Executes a highly-optimized 64-bit atomic read without locking the CPU entirely. If the buffer has accumulated 1024 intercepted packets, OR if `50,000` system time-ticks (5 milliseconds) have passed since the last alert, we trigger `KeSetEvent`, waking up the Python UI.

```cpp
NTSTATUS RegisterWfpCallouts(PDEVICE_OBJECT deviceObject) {
    ...
    status = FwpsCalloutRegister0(deviceObject, &callout, &calloutIds[0]);
```
Performs the lower-level integration hooking the `ClassifyFn` pointers statically against the device object representing our `secAI` driver structure. 

```cpp
NTSTATUS RegisterBfeFilters() {
    ...
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING; // Change from INSPECTION
```
Pumps out the user-mode visible filters into the Base Filtering Engine mapping to the callouts we just installed. Crucially assigns `TERMINATING` rather than `INSPECTION` giving us strict lethal power over network streams. 

```cpp
void UnregisterBfeFilters() {
    if (g_EngineHandle) {
        FwpmEngineClose0(g_EngineHandle); 
        g_EngineHandle = NULL;
    }
}
```
Teardown handler that safely closes the BFE session and clears the handle, executing during `net stop secAI` unloading instructions.
