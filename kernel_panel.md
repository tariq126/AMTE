# Kernel Panel Documentation

This document provides a line-by-line detailed explanation of the `kernel_panel.py` module in the SecAI architecture. This file acts as the explicit Python bridge interacting with the raw Windows Kernel APIs (`DeviceIoControl`), managing the shared ring buffer natively, and transmitting command telemetry to the `SecAIDriver`.

## Errors and Issues Solved

Bridging a managed, garbage-collected language like Python directly into chaotic lock-free memory mapped by a C++ driver spawned several deeply complex bugs:

1. **Handle Truncation (64-bit Memory Corruption):**
   * **Issue:** Calls to `CreateFileW` and `OpenEventW` were suddenly failing with "Invalid Handle" when porting the script to modern systems. By default, `ctypes` natively assumes every underlying C function returns a 32-bit `int`. On x64 Windows, handles are 64-bit addresses. Python was silently chopping off the top 32 bits of the driver's memory address, destroying the handles instantly.
   * **Solution:** Explicitly enforced the Ctypes signatures via `.restype = wintypes.HANDLE` for all API calls, preventing addressing truncation.

2. **Garbage Collection (GC) Tearing Down Shared Memory:**
   * **Issue:** Sometime after running `kp_init_driver()`, the ring buffer would randomly stop receiving packets and start reading pure zeros. The local `buffer_type` memory mapping variable was falling out of the function scope, causing Python's Garbage Collector to automatically free the object and implicitly unmap the underlying 16MB driver memory.
   * **Solution:** A global `_raw_buffer` placeholder was established. Attaching the `from_address` mapping to this global forever prevents the GC from freeing the raw memory allocation while the driver relies on it.

3. **NumPy Read-Only Check (`ValueError` Crash):**
   * **Issue:** After pulling a batch of packets, Python attempted to update the `tail` parameter in the memory header to notify the driver it was finished reading. However, `np.frombuffer()` produces inherently *read-only* arrays. Attempting `header_arr['tail'][0] = head` instantly threw a fatal `ValueError`.
   * **Solution:** Bypassed the NumPy wrapper entirely for the write phase, directly mutating the raw underlying block using pointer arithmetic: `ctypes.c_uint64.from_buffer(_raw_buffer, 72).value = head`.

4. **Multi-core "Tearing" & Hardware Order Faults:**
   * **Issue:** Even with the `tail` properly updating, the buffer still stalled. Modern CPU architectures execute operations out of order. Reading `head`, reading `tail`, and modifying data were getting jumbled across CPU caches before they reached physical RAM. 
   * **Solution:** Leveraged `kernel32.FlushProcessWriteBuffers()`, which natively fires an Inter-Processor Interrupt (IPI) sending a hardware-level memory barrier (mfence) to every CPU core on the motherboard, locking execution order strictly matching our ring buffer sequence.

5. **API Boundary Leaks:**
   * **Issue:** External UI components were previously importing numpy, the raw buffer, and executing array slicing mathematics directly just to discover how many packets had dropped.
   * **Solution:** Designed and encapsulated the `kp_get_metrics()` abstraction hook shielding the complex `mview` memory math, forcing clean UI architecture.

---

## Code Walkthrough: kernel_panel.py

```python
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import numpy as np
from data_contracts import header_dtype, packet_dtype
```
Core dependencies. `ctypes` allows execution of native C Windows API commands. `numpy` executes high-performance memory array computations. Finally, `data_contracts.py` dictates the specific byte offsets.

```python
kernel32 = ctypes.windll.kernel32
```
Binds the Windows system library natively executing file-system, memory mapping, and event handling operations.

```python
kernel32.CreateFileW.restype           = wintypes.HANDLE
kernel32.OpenEventW.restype            = wintypes.HANDLE
kernel32.CloseHandle.restype           = wintypes.BOOL
kernel32.DeviceIoControl.restype       = wintypes.BOOL
kernel32.FlushProcessWriteBuffers.restype = None
```
**Critical Patch Zone:** Resolves the 64-bit handle truncation bug. It rigorously instructs Python on how many bits to physically expect Windows to return after executing a raw system call. 

```python
SYNCHRONIZE = 0x00100000
SEC_AI_DEVICE_TYPE = 40000
METHOD_BUFFERED = 0
FILE_ANY_ACCESS = 0
```
Maps the fundamental IOCTL constants natively exactly mirroring the Microsoft C++ `Ioctls.h` driver header counterparts.

```python
def CTL_CODE(device_type, function, method, access):
    return (device_type << 16) | (access << 14) | (function << 2) | method
```
Bitwise mathematical reconstruction of the C++ `#define CTL_CODE` macro. Constructs the specific 32-bit hex command codes the driver hardware listens for.

```python
IOCTL_START_CAPTURE     = CTL_CODE(SEC_AI_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
...
IOCTL_STOP_CAPTURE      = CTL_CODE(SEC_AI_DEVICE_TYPE, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
```
Invokes the custom function above to instantiate the routing tables dictating exactly which hex commands interact with which driver functions.

```python
@dataclass
class BlockRuleV1:
    ...
```
A lightweight python-native representation of the firewall rules. Makes passing firewall rules from the Dashboard code into this script vastly cleaner.

```python
class BlockRuleStruct(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("ip_version", ctypes.c_uint8),
        ...
        ("_pad0", ctypes.c_uint8 * 2),     # ADDED PADDING
        ...
```
The heavily un-abstracted representation of the actual driver C++ struct layout. The `_pack_ = 1` enforces exactly the same 1-byte alignment mechanism done via `#pragma pack(1)` in C++. The explicit string types (e.g., `_pad0`) rigorously enforce 64-byte structural boundaries averting BSOD alignment faults.

```python
def kp_init_driver():
    global _driver_handle, _packet_event, _shared_memory_view, _raw_buffer
```
Initialization hook run when the script launches. Declares global variables guarding against garbage collection logic tearing down active telemetry.

```python
    _driver_handle = kernel32.CreateFileW(
        r"\\.\SecAIDriver",
        0xC0000000, # GENERIC_READ | GENERIC_WRITE
        ...
```
Utilizes the low-level Windows API to formally request a handle interacting directly with the SecAIDriver device map exposed in the kernel space.

```python
    _packet_event = kernel32.OpenEventW(
        SYNCHRONIZE,
        False,
        r"Global\SecAIPacketEvent"
    )
```
Acquires the Notification Event the kernel established via `IoCreateNotificationEvent`. `SYNCHRONIZE` access specifically allows Python threads to "sleep" while listening for this event flag utilizing `WaitForSingleObject` without polling the CPU to death.

```python
    success = kernel32.DeviceIoControl( ... IOCTL_START_CAPTURE ... )
```
Contacts the switchboard triggering the `kernel` mapping phase. Requests that the driver return the 8-byte pointer marking where the raw Ring Buffer memory was allocated.

```python
    if success and out_ptr.value:
        SHARED_MEMORY_SIZE = 1024 * 1024 * 16
        buffer_type = ctypes.c_uint8 * SHARED_MEMORY_SIZE
        _raw_buffer = buffer_type.from_address(out_ptr.value)
        _shared_memory_view = memoryview(_raw_buffer)
```
Retrieves the 16MB pointer (`out_ptr`), creates a fixed-length C array, assigns the absolute memory location to it, and wraps it into a Python `memoryview`. Utilizing the global `_raw_buffer` completely shields it from Garbage Collection teardown.

```python
def kp_add_block_rule(rule: BlockRuleV1):
    ...
    struct = BlockRuleStruct()
    ...
```
Receives the Python dataclass, maps every single attribute securely into the 64-byte C++ equivalent `BlockRuleStruct`, preparing it for transition across the boundary.

```python
    success = kernel32.DeviceIoControl( ... IOCTL_ADD_BLOCK_RULE ... ctypes.byref(struct) ... )
```
Transfers the newly constructed 64-byte struct into Kernel limits utilizing `METHOD_BUFFERED` making certain the OS performs the memory security copy explicitly.

```python
def kp_get_active_rules() -> list:
    ...
    buffer_type = BlockRuleStruct * 1024
    out_buffer   = buffer_type()
```
Pre-allocates an array spanning 1024 rule structs. Mimics the exact `MAX_BLOCK_RULES` array structure present natively in the driver.

```python
    success = kernel32.DeviceIoControl( ... IOCTL_GET_BLOCK_RULES ... )
    ...
    struct_size = ctypes.sizeof(BlockRuleStruct)
    rule_count  = bytes_returned.value // struct_size
```
After executing the fetch command, it uses mathematical division derived via `sizeof` determining specifically how many functional rules were ported back out without sequentially scanning 1,024 memory blocks looking for null pointers. Assembles them into standard dictionaries and returns the array.

```python
def kp_remove_block_rule(target_port: int) -> bool:
    ...
    port_c = ctypes.c_uint16(target_port)
    ...
```
Maps the targeted removal port directly to an unsigned 16-bit payload routing the instruction into `IOCTL_REMOVE_BLOCK_RULE`, bypassing arbitrary Python integers natively.

```python
def kp_read_batch(shared_mem_buffer):
    ...
    header_arr = np.frombuffer(header_view, dtype=header_dtype)
    head = int(header_arr['head'][0])
```
Starts constructing the lock-free array extraction. Decodes explicitly the first 192 bytes isolating the control header variables and querying where the write `head` pointer currently rests.

```python
    kernel32.FlushProcessWriteBuffers()
    tail = int(header_arr['tail'][0])
```
Executes the hardware-level `mfence` memory-barrier to combat physical out-of-order execution before retrieving the `tail` coordinate tracking where Python left off.

```python
    if head >= tail:
        count = head - tail
        end_byte = head * packet_size
        raw_bytes = data_view[start_byte:end_byte]
        records = np.frombuffer(raw_bytes, dtype=packet_dtype)
        packets = np.copy(records)
```
The straight-line buffer execution block. Uses mathematically isolated subsets cutting direct bytes out of the layout view. Calling `np.copy` is an incredibly important security necessity explicitly breaking the pointer linkage separating Python vectors from real-time driver overwrites while iterating the resulting `packets`.

```python
    else:
        ...
        packets = np.concatenate([records_1, records_2])
```
Performs the "Wrap Around" phase resolving out-of-bounds overlaps cleanly without crashing the kernel pointer mathematics. Concat naturally creates a disconnected array resolving the numpy `np.copy` necessity.

```python
    kernel32.FlushProcessWriteBuffers()
    ctypes.c_uint64.from_buffer(_raw_buffer, 72).value = head
```
Re-engages the hardware memory barrier to definitively lock the buffer's execution pipeline. Utilizing structural pointer overrides (`from_buffer... 72`) bypassing the read-only restrictions updating the tail natively reflecting what was previously read.

```python
def kp_get_metrics():
    ...
    return ( int(header_arr['head'][0]), int(header_arr['tail'][0]), ... )
```
Establishes the API encapsulation allowing parallel logic testing structures to cleanly access the ring buffer metrics without manipulating global variables directly.

```python
def kp_close_driver():
    ...
    kernel32.CloseHandle(_driver_handle)
```
Teardown phase safely abandoning pointer chains and closing handles natively invoking the OS subsystem instructing `EvtFileCleanup` to execute on the C++ side natively routing memory de-allocations gracefully.
