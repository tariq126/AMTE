# Data Contracts Documentation

This document provides a line-by-line breakdown of `data_contracts.py`, focusing on how Python replicates the exact memory layout mapped natively by the C++ kernel driver (`PacketRecord.h`). This is the absolute core of the zero-copy shared memory architecture, allowing Python to read exactly what the hardware writes without any expensive data serialization (like JSON or Protobuf).

## Errors and Issues Solved

Synchronizing native C++ memory across the kernel-to-user boundary into a dynamic language like Python requires mathematically strict constraints avoiding some previously devastating issues:

1. **Hardware "False Sharing" and CPU Cache Stalling:**
   * **Issue:** In early driver versions, the SPSC ring buffer was slow and bottlenecking. The `head` (writer) and `tail` (reader) 64-bit pointers lived directly next to each other in memory. Modern CPU cache lines are 64 bytes long. When the kernel wrote to `head` on Core 1, and Python read `tail` on Core 2, the CPU constantly locked and flushed the entire memory line back and forth, collapsing performance.
   * **Solution:** We introduced 56-byte pads (`pad1` and `pad2`) between `head` and `tail`. This forcefully isolates the pointers, guaranteeing `head` occupies its own hardware cache line distinct from `tail`, allowing the Kernel and Python to touch memory independently at maximum speed.

2. **Zero-Copy Memory Misalignment and Structure Tearing:**
   * **Issue:** Python was originally reading garbage IP addresses and invalid timestamps. This was because compiled C++ naturally throws in implicit padding to align variables which Python's NumPy structured types didn't know about. The arrays were shifted out of phase.
   * **Solution:** The driver was updated to use `#pragma pack(1)` and static asserts ensuring the header is immutably 192 bytes. `data_contracts.py` was painstakingly rebuilt using exact explicit dictionary offsets matching those 192 bytes perfectly. 

3. **NumPy Indexing Faults:**
   * **Issue:** If NumPy miscalculates the size of the telemetry chunk, indexing the buffer (like `array[5]`) jumps to the wrong memory location, pulling half-packet values out of thin air.
   * **Solution:** `itemsize: 192` and `itemsize: 64` were hardcoded explicitly into the NumPy dictionary, ensuring element strides exactly map to the memory array limits without guesswork.

---

## Code Walkthrough: data_contracts.py

```python
import numpy as np
```
Imports NumPy. We leverage NumPy's `dtype` library heavily here because it is a C-accelerated library specifically designed for parsing rigid structures of raw memory bytes.

```python
# SharedMemoryHeader (includes 56-byte padding to prevent false sharing and aligns to 64 bytes)
# The C++ alignas(64) pads the 152 bytes of defined members up to 192 bytes.
header_dtype = np.dtype({
```
Initializes the construction of the control header definition. This dictionary structurally maps bytes `0` through `191` of the shared memory pool.

```python
    'names': [
        'schema_version', '_pad0',
        'head', 'pad1',
        'tail', 'pad2',
        'capacity', 'dropped_packets'
    ],
```
Creates human-readable labels so the Python backend can interact with the struct attributes naturally (e.g., `header['head']`). `pad1` and `pad2` are specifically mapped purely to be safely skipped.

```python
    'formats': [
        np.uint32, np.uint32,
        np.uint64, '56V',
        np.uint64, '56V',
        np.uint64, np.uint64
    ],
```
Dictates exactly what primitive type NumPy should interpret raw bits as. 
* Uses exactly sized `uint` numbers mimicking C++ `UINT32` and `UINT64`.
* `'56V'` represents 56 bytes of pure `Void`. This tells Python: "Understand there are 56 bytes of memory here, but do not attempt to read or convert them into variables."

```python
    'offsets': [
        0, 4,
        8, 16,
        72, 80,
        136, 144
    ],
```
The most critical mechanism in the file. Defeats compiler layout ambiguities by telling NumPy the explicit hardcoded byte offset where each specific variable begins. For example, it guarantees it won't check for `tail` until byte 72.

```python
    'itemsize': 192
})
```
Caps the dictionary, instructing numpy that the single `SharedMemoryHeader` covers exactly 192 bytes of the mapped pool.

```python
# Exactly 64 bytes = 1 CPU Cache Line
packet_dtype = np.dtype({
```
Begins constructing the layout representing a single individual intercepted network packet.

```python
    'names': [
        'mono_ts_ns', 'schema_version', 'if_index', 'captured_len',
        'wire_len', 'src_port', 'dst_port', 'direction', 'ip_version',
        'proto', 'tcp_flags', 'src_ip', 'dst_ip'
    ],
```
Defines the dictionary string names mirroring the exact `PacketRecordV1` variables in C++.

```python
    'formats': [
        np.uint64, np.uint32, np.uint32, np.uint32,
        np.uint32, np.uint16, np.uint16, np.uint8, np.uint8,
        np.uint8, np.uint8, (np.uint8, 16), (np.uint8, 16)
    ],
```
Establishes the primitive memory lengths mapping against `PacketRecord.h`. For the heavy structures like IPv6 addresses at the end, it uses `(np.uint8, 16)`, indicating a clustered 16-byte fixed-length array representing the IP address bytes.

```python
    'offsets': [
        0, 8, 12, 16,
        20, 24, 26, 28, 29,
        30, 31, 32, 48
    ],
```
Explicit hardcoded matrix mapping every single packet field down to the absolute bit offset. For example: `ip_version` occupies precisely the 29th byte of an arriving packet struct, while the `dst_ip` starts exactly at byte 48.

```python
    'itemsize': 64
})
```
Explicitly dictates the array stride length for the packet segment. Because it's 64, calling `Array[1]` fetches bytes 64-127, while `Array[5]` natively jumps right to memory boundaries 320-383 instantly without computing overhead. It operates entirely by math mimicking zero-copy natively.
