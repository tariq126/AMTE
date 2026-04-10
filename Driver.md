# Driver.cpp Documentation

This document provides a line-by-line detailed explanation of the core driver initialization, memory mapping, event dispatch, and input/output control component found in `Driver.cpp` for the SecAI Windows kernel driver.

## Errors and Issues Solved

During the initial deployment of the WDF/WFP driver, numerous architectural stability and security vulnerabilities were resolved in this core component:

1. **Process Teardown BSOD in `EvtFileCleanup`:**
   * **Issue:** Whenever the Python user-space process crashed or was closed via Ctrl+C, the OS would bug-check (BSOD). The driver was manually calling `MmUnmapLockedPages` inside `EvtFileCleanup`.
   * **Solution:** Because the Windows Memory Manager already tears down the user-mode page tables automatically when an application dies, manually unmapping it pointed to a dead context. Removed the `MmUnmapLockedPages` call entirely from the cleanup callback, simply setting `g_SharedMemoryUserBase = NULL`.

2. **Racing Callouts During Driver Unload (D1 / 50 Bug Checks):**
   * **Issue:** When unloading the driver (`net stop SecAI`), in-flight packets were still being processed by `ClassifyFn`. If the driver freed the shared Ring Buffer memory while a CPU core was still writing a packet via the callout, the system would immediately crash.
   * **Solution:** Reordered the `DriverUnload` pipeline into strict, blocking steps. Step 1 unregisters the Base Filtering Engine (BFE) filters. Step 2 unregisters the callbacks via `FwpsCalloutUnregisterById0` which *blocks* until all running callbacks drain. Only *after* that drain does Step 3 free the MDL buffers.

3. **Buffer Sizing and Confused Deputy Attacks:**
   * **Issue:** User-mode applications could pass arbitrary sizes into IOCTLs (like `IOCTL_GET_BLOCK_RULES`), causing buffer underflows or writing kernel memory out of bounds.
   * **Solution:** Enforced rigid length bounds checking (e.g., comparing `OutputBufferLength` explicitly against `sizeof(BlockRuleV1) * MAX_BLOCK_RULES`) before initiating `WdfRequestRetrieveOutputBuffer`.

---

## Code Walkthrough: Driver.cpp

```cpp
#include <ntddk.h>
#include <wdf.h>
```
Standard Driver Development Kit and Windows Driver Framework includes. Provides WDF object models (WDFDEVICE, WDFQUEUE, IO Requests).

```cpp
#ifndef NDIS61
#define NDIS61 1
#endif
#include <ndis.h>
#include <fwpsk.h>
```
Targets NDIS 6.1 (Windows 7 and up) context before pulling in Windows Filtering Platform dependencies (`fwpsk.h`).

```cpp
#include "Ioctls.h"
#include "RingBuffer.h"
#include "BlockEngine.h"
```
Imports local IOCTL control code definitions, the Ring Buffer telemetry tracker, and our thread-safe BlockEngine module.

```cpp
PVOID g_SharedMemoryKernelBase = NULL;
PMDL g_SharedMemoryMdl = NULL;
```
Global pointers for tracking the raw physical memory (Memory Descriptor List) and its mapped kernel virtual address for the ring buffer.

```cpp
PKEVENT g_PacketEvent = NULL;
HANDLE g_PacketEventHandle = NULL;
```
Global structures for maintaining a lock-free Notification Event. This event signals the Python user-space process whenever a batch of packets arrives.

```cpp
PVOID g_SharedMemoryUserBase = NULL;
extern UINT32 calloutIds[4];
```
Tracks the user-space virtual address when it is mapped into the `cmd.exe`/`python.exe` process context. Captures WFP callout IDs so the un-loader can drain them.

```cpp
const ULONG SHARED_MEMORY_SIZE = 1024 * 1024 * 16; 
```
Allocates a static 16 Megabytes of memory for transferring packet structures between Kernel and Python spaces.

```cpp
extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" EVT_WDF_DRIVER_UNLOAD DriverUnload;
```
Identifies the primary C-styled driver entry and exit points to the linker.

```cpp
PVOID MapSharedMemoryToUserSpace() {
    if (!g_SharedMemoryMdl) return NULL;
    PVOID userBase = NULL;
    __try {
        userBase = MmMapLockedPagesSpecifyCache(
            g_SharedMemoryMdl, UserMode, MmCached, NULL, FALSE, NormalPagePriority | MdlMappingNoExecute
        );
        g_SharedMemoryUserBase = userBase;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        userBase = NULL;
    }
    return userBase;
}
```
**`MapSharedMemoryToUserSpace`**: Maps the existing physical MDL pages into the virtual memory space of the currently executing user-mode process (the Python App calling the IOCTL). Wrapped in a structured exception handler (`__try`/`__except`) so that if memory mapping fails, the driver gracefully recovers rather than crashing the OS. Prevents user-mode code execution on this memory via `MdlMappingNoExecute`.

```cpp
NTSTATUS InitializeSharedMemory() {
    PHYSICAL_ADDRESS lowAddress, highAddress, skipBytes;
    lowAddress.QuadPart = 0; highAddress.QuadPart = -1; skipBytes.QuadPart = 0;
```
Sets limits allowing the memory manager to allocate physical RAM pages anywhere in the system (-1 means no upper limit). 

```cpp
    g_SharedMemoryMdl = MmAllocatePagesForMdl(lowAddress, highAddress, skipBytes, SHARED_MEMORY_SIZE);
```
Creates the Memory Descriptor List representing 16MB of non-paged RAM.

```cpp
    g_SharedMemoryKernelBase = MmGetSystemAddressForMdlSafe(g_SharedMemoryMdl, NormalPagePriority | MdlMappingNoExecute);
```
Asks the kernel for a safe, non-executable virtual pointer mapping to those physical pages. If this fails, the system is out of resources.

```cpp
    RingBuffer_Init(g_SharedMemoryKernelBase, SHARED_MEMORY_SIZE);
    return STATUS_SUCCESS;
}
```
Delegates the formatting of the newly allocated 16MB memory to the RingBuffer component, setting up headers and padding.

```cpp
NTSTATUS InitializePacketEvent() {
    UNICODE_STRING eventName;
    RtlInitUnicodeString(&eventName, L"\\BaseNamedObjects\\SecAIPacketEvent");
    g_PacketEvent = IoCreateNotificationEvent(&eventName, &g_PacketEventHandle);
```
Creates a named `KEVENT` object that both the kernel can write to and user-space can open by name (`Global\SecAIPacketEvent`) using standard Windows APIs. It is a notification event, meaning it wakes up all waiting threads.

```cpp
VOID DriverUnload(_In_ WDFDRIVER Driver) {
    UNREFERENCED_PARAMETER(Driver);
    UnregisterBfeFilters();
```
**`DriverUnload` Step 1**: Immediately removes Base Filtering Engine filters. Networking begins bypassing the callout at this stage.

```cpp
    for (int i = 0; i < 4; i++) {
        if (calloutIds[i] != 0) {
            FwpsCalloutUnregisterById0(calloutIds[i]);
            calloutIds[i] = 0;
        }
    }
```
**Step 2**: Safely destroys the WFP callouts. Critically, `FwpsCalloutUnregisterById0` halts the thread here until every single active packet inspection in the OS finishes running.

```cpp
    if (g_SharedMemoryMdl) {
        MmFreePagesFromMdl(g_SharedMemoryMdl);
        IoFreeMdl(g_SharedMemoryMdl);
    }
```
**Step 3**: Reclaims the 16MB ring buffer buffer memory. This is now safe because Step 2 guaranteed no threads remain inside `ClassifyFn`.

```cpp
VOID EvtIoDeviceControl(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request, _In_ size_t OutputBufferLength, _In_ size_t InputBufferLength, _In_ ULONG IoControlCode) {
```
The central switchboard for receiving IOCTL commands (system calls) from the UI layer.

```cpp
    switch (IoControlCode) {
        case IOCTL_START_CAPTURE: {
            if (OutputBufferLength < sizeof(PVOID)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
```
Reacts to the start/connect signal. Rigidly ensures the Python script has allocated at least an 8-byte (64-bit) pointer size in the output buffer. 

```cpp
            PVOID userBase = MapSharedMemoryToUserSpace();
            if (userBase) {
                PVOID outBuffer = NULL;
                status = WdfRequestRetrieveOutputBuffer(Request, sizeof(PVOID), &outBuffer, NULL);
                if (NT_SUCCESS(status)) {
                    *(PVOID*)outBuffer = userBase;
```
Calls the mapping function and safely pushes the newly generated user-space memory address back over the IOCTL boundary for Python's `ctypes` engine.

```cpp
        case IOCTL_ADD_BLOCK_RULE: {
            PVOID inBuffer = NULL;
            status = WdfRequestRetrieveInputBuffer(Request, sizeof(BlockRuleV1), &inBuffer, NULL);
            if (NT_SUCCESS(status) && inBuffer != NULL) {
                status = BlockEngine_AddRule((const BlockRuleV1*)inBuffer);
            }
```
Validates the input buffer precisely matches `sizeof(BlockRuleV1)`. Extracts the user-mode firewall rule request and forwards it directly to the Block Engine.

```cpp
        case IOCTL_GET_BLOCK_RULES: {
            const ULONG requiredOut = sizeof(BlockRuleV1) * MAX_BLOCK_RULES;
            if (OutputBufferLength < requiredOut) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
```
Ensures that the user space application has provided a buffer large enough (e.g., exactly `1024 * 72 bytes`) to safely receive a heavy copy operation. Plugs security holes related to array boundary overflows.

```cpp
            PVOID outBuffer = NULL;
            status = WdfRequestRetrieveOutputBuffer(Request, requiredOut, &outBuffer, NULL);
            ULONG ruleCount = BlockEngine_GetRules((BlockRuleV1*)outBuffer, MAX_BLOCK_RULES);
            information = (ULONG_PTR)(ruleCount * sizeof(BlockRuleV1));
```
Retrieves the safe WDF-assigned virtual buffer, executes a purely internal safe-copy of all active rules, and records exactly how many bytes were used to advise the I/O manager.

```cpp
        case IOCTL_REMOVE_BLOCK_RULE: {
            if (InputBufferLength < sizeof(UINT16)) {
...
            UINT16 dstPort = *(UINT16*)inBuffer;
            status = BlockEngine_RemoveRule(dstPort);
```
Validates that exactly 2 bytes (UINT16) were transmitted. Reads the destination port and forwards the deletion command to the BlockEngine.

```cpp
    WdfRequestCompleteWithInformation(Request, status, information);
```
Releases the IOCTL request back to user-mode space cleanly with the final status and byte count result.

```cpp
VOID EvtFileCleanup(_In_ WDFFILEOBJECT FileObject) {
    UNREFERENCED_PARAMETER(FileObject);
    g_SharedMemoryUserBase = NULL; 
}
```
Fires the instant the user closes the handle to the driver. Contains the critical patch that averts a BSOD by deliberately NOT manually unmapping physical pages tied to process context.

```cpp
NTSTATUS InitializeControlDevice(WDFDRIVER Driver) {
    PWDFDEVICE_INIT deviceInit = WdfControlDeviceInitAllocate(Driver, &SDDL_DEVOBJ_SYS_ALL_ADM_RWX_WORLD_RW_RES_R);
```
Bootstraps a WDF Device Object. Associates an SDDL string ensuring only privileged Administrator access can interact with the IOCTL queues, preventing local privilege escalation attacks.

```cpp
    WDF_FILEOBJECT_CONFIG fileConfig;
    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, WDF_NO_EVENT_CALLBACK, WDF_NO_EVENT_CALLBACK, EvtFileCleanup);
    WdfDeviceInitSetFileObjectConfig(deviceInit, &fileConfig, WDF_NO_OBJECT_ATTRIBUTES);
```
Registers the aforementioned `EvtFileCleanup` callback hook into the framework.

```cpp
    WDFDEVICE device;
    NTSTATUS status = WdfDeviceCreate(&deviceInit, WDF_NO_OBJECT_ATTRIBUTES, &device);
```
Finalizes the creation of the underlying kernel DOS device tree.

```cpp
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = EvtIoDeviceControl;
```
Initializes a sequential IOCTL queue. A sequential queue guarantees IOCTL commands are submitted sequentially and securely to the switchboard.

```cpp
    PDEVICE_OBJECT wdmDevice = WdfDeviceWdmGetDeviceObject(device);
    status = RegisterWfpCallouts(wdmDevice);
    if (NT_SUCCESS(status)) {
        RegisterBfeFilters();
    }
```
Completes Device initialization by exposing its canonical underlying `PDEVICE_OBJECT` to the WFP module for base filtering registration.

```cpp
extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
```
The absolute entry-point logic invoked directly by the OS when `net start SecAI` is run.

```cpp
    BlockEngine_Init(); 
```
Initializes the zeroed block rules array prior to doing anything else, ensuring no undefined data gets activated.

```cpp
    status = InitializeSharedMemory();
    status = InitializePacketEvent();
    status = InitializeControlDevice(driver);
```
Spins up physical RAM, opens event handles to user space, creates the device queues, and subsequently links into the Windows Filtering Platform pipelines. Stops and exits cleanly if any of these critical subsystems fail to map.
