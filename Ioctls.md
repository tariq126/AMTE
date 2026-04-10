# Ioctls.h Documentation

This document provides a line-by-line detailed explanation of the `Ioctls.h` component in the SecAI Windows kernel driver. This file serves as the strict numeric "contract" between the underlying kernel driver and the user-mode application (the Python/C++ UI dashboard), establishing exactly which commands are accessible.

## Errors and Issues Solved

During the expansion of the firewall capabilities and IOCTL implementations, several issues arose concerning IOCTL registration and memory access paths:

1. **IOCTL Code Collisions and System Misrouting:**
   * **Issue:** When adding the new firewall features, the `IOCTL_GET_BLOCK_RULES` command was originally assigned to the function code `0x803`. However, `0x803` was already natively used by `IOCTL_STOP_CAPTURE`. This collision caused unpredictable misrouting constraints; instructing the driver to dump the latest block rules to the dashboard could cause the driver to erroneously terminate the packet capture session entirely.
   * **Solution:** `IOCTL_STOP_CAPTURE` was aggressively relocated to a new, distinct function code (`0x806`). Documentation and comments were added here to enforce that Python ctypes bridging code must correspondingly utilize `0x806` to avert hitting the old memory location.
   
2. **Kernel Data Truncation / User Pointer Invalidations:**
   * **Issue:** User-mode applications are notorious for freeing active memory pointers or passing invalid memory pointers rapidly. If the kernel driver reads a raw pointer that had just been de-allocated by the Python garbage collector, the system would blue screen immediately due to page fault in non-paged areas (Bugcheck 0x50 and 0xD1).
   * **Solution:** We explicitly standardized every single IOCTL on the memory type `METHOD_BUFFERED`. This dictates that the Windows I/O subsystem intercepts the request, safely copies the user's variables into an isolated pool of kernel memory, and ensures the kernel driver never touches the unpredictable user-mode pointers directly.

---

## Code Walkthrough: Ioctls.h

```cpp
#pragma once
```
Instructs the C++ preprocessor to only include this header file once during compilation, preventing redundant macro redefinitions that could otherwise cause compiler looping failures.

```cpp
#include <ntddk.h>
#include <wdf.h>
```
Includes the necessary Windows Driver Framework definitions and core macros. This is strictly required to access the `CTL_CODE` builder macro and the file access constant `FILE_ANY_ACCESS`.

```cpp
#define SEC_AI_DEVICE_TYPE 40000
```
Defines a custom hardware device type in the standard custom range block (`0x8000` to `0xFFFF`). 40000 equates to `0x9C40` in hex. This segregates our commands and guarantees our device type operates distinctly from common predefined Microsoft drivers like Keyboards or Hard Drives.

```cpp
// Define the IOCTL codes for communication between User-Mode Python / C++ Bridge and the Kernel Driver
#define IOCTL_START_CAPTURE \
    CTL_CODE(SEC_AI_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
```
Generates the hexadecimal system control code that the Python application will transmit to initialize the driver's ring buffer memory telemetry pipeline. 
* `SEC_AI_DEVICE_TYPE` integrates our isolated custom tag.
* `0x800` is the localized function index.
* `METHOD_BUFFERED` instructs the OS memory manager to copy data buffers securely between the User and Kernel boundaries.
* `FILE_ANY_ACCESS` configures validation determining that the caller only requires generic handle access rather than specifically locked Read vs Write capabilities.

```cpp
#define IOCTL_ADD_BLOCK_RULE \
    CTL_CODE(SEC_AI_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
```
Generates function code `0x802`. Triggered when the Python dashboard injects a structured `BlockRuleV1` into the kernel to enforce IPs, Protocols, or Ports filtering onto the network stream.

```cpp
// Returns all active BlockRuleV1 entries to user-mode as a flat array
#define IOCTL_GET_BLOCK_RULES \
    CTL_CODE(SEC_AI_DEVICE_TYPE, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
```
Generates function code `0x803`. Initiated by the UI dashboard when it queries the kernel to dump the live, active access-control structure array back up through user space across the ctypes bridge. 

```cpp
// Receives a dst_port (UINT16) from user-mode and atomically deactivates the matching rule
#define IOCTL_REMOVE_BLOCK_RULE \
    CTL_CODE(SEC_AI_DEVICE_TYPE, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
```
Generates function code `0x804`. Pushed by the user script to dynamically eliminate an active network filtering rule. Driven securely via `METHOD_BUFFERED`, which guarantees the `UINT16 dst_port` argument is solidly anchored into system ram prior to `BlockEngine_RemoveRule` intercepting it.

```cpp
#define IOCTL_GET_STATS \
    CTL_CODE(SEC_AI_DEVICE_TYPE, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
```
Generates function code `0x805`. Designed as a diagnostic route utilized to query live ring buffer flow analytics, drop counters, and connection limits.

```cpp
// NOTE: 0x803 was previously IOCTL_STOP_CAPTURE; it has been moved to 0x806
//       to avoid colliding with IOCTL_GET_BLOCK_RULES. Update any Python code
//       that used the old 0x803 stop value to use 0x806 instead.
#define IOCTL_STOP_CAPTURE \
    CTL_CODE(SEC_AI_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
```
Generates function code `0x806`. Acts as the teardown mechanism forcing the Windows memory manager to release user-mode mappings gracefully via `EvtIoDeviceControl` when terminating the application session. The inline comment serves as a permanent breadcrumb outlining the previously addressed mapping collision over `0x803`.
